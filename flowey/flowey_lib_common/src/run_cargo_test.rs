// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Test

use crate::run_cargo_build::CargoBuildProfile;
use crate::run_cargo_build::CargoFeatureSet;
use crate::run_cargo_nextest_run::build_params::TestPackages;
use flowey::node::prelude::*;

flowey_request! {
    pub struct Request {
        pub packages: TestPackages,
        pub profile: CargoBuildProfile,
        pub features: CargoFeatureSet,
        pub target: target_lexicon::Triple,
        pub extra_args: Option<Vec<String>>,
        pub output: WriteVar<String>,
    }
}

new_flow_node!(struct Node);

impl FlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<crate::cfg_cargo_common_flags::Node>();
        ctx.import::<crate::install_rust::Node>();
        ctx.import::<crate::install_rust::Node>();
    }

    fn emit(requests: Vec<Self::Request>, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let rust_toolchain = ctx.reqv(crate::install_rust::Request::GetRustupToolchain);
        let flags = ctx.reqv(crate::cfg_cargo_common_flags::Request::GetFlags);

        for Request {
            packages,
            profile,
            features,
            target,
            extra_args,
            output,
        } in requests
        {
            ctx.req(crate::install_rust::Request::InstallTargetTriple(
                target.clone(),
            ));

            ctx.emit_rust_step("cargo test", |ctx| {
                let output = output.claim(ctx);
                let rust_toolchain = rust_toolchain.clone().claim(ctx);
                let flags = flags.clone().claim(ctx);
                move |rt| {
                    let rust_toolchain = rt.read(rust_toolchain);
                    let flags = rt.read(flags);

                    let crate::cfg_cargo_common_flags::Flags { locked, verbose } = flags;
                    let locked = locked.then_some("--locked");
                    let verbose = verbose.then_some("--verbose");

                    let target = target.to_string();

                    let cargo_profile = match &profile {
                        CargoBuildProfile::Debug => "dev",
                        CargoBuildProfile::Release => "release",
                        CargoBuildProfile::Custom(s) => s,
                    };

                    let mut args = Vec::new();
                    args.extend(locked.map(Into::into));
                    args.extend(verbose.map(Into::into));
                    let packages: Vec<String> = {
                        // exclude benches
                        let mut v = vec!["--tests".into(), "--bins".into()];

                        match packages {
                            TestPackages::Workspace { exclude } => {
                                v.push("--workspace".into());
                                for crate_name in exclude {
                                    v.push("--exclude".into());
                                    v.push(crate_name);
                                }
                            }
                            TestPackages::Crates { crates } => {
                                for crate_name in crates {
                                    v.push("-p".into());
                                    v.push(crate_name);
                                }
                            }
                        }

                        v
                    };

                    let feature_strings = features.to_cargo_arg_strings();
                    args.extend(feature_strings.iter().cloned());
                    args.push("--target".into());
                    args.push(target);
                    args.push("--profile".into());
                    args.push(cargo_profile.into());
                    args.extend(packages);

                    let sh = xshell::Shell::new()?;

                    let mut cmd = if let Some(rust_toolchain) = &rust_toolchain {
                        xshell::cmd!(sh, "rustup run {rust_toolchain} cargo test")
                    } else {
                        xshell::cmd!(sh, "cargo test")
                    };

                    // if running in CI, no need to waste time with incremental
                    // build artifacts
                    if !matches!(rt.backend(), FlowBackend::Local) {
                        cmd = cmd.env("CARGO_INCREMENTAL", "0");
                    }

                    if let Some(extra_args) = extra_args {
                        args.push("--".into());
                        args.extend(extra_args);
                    }

                    let stdout_output = cmd.args(args).read()?;
                    rt.write(output, &stdout_output);

                    Ok(())
                }
            });
        }

        Ok(())
    }
}
