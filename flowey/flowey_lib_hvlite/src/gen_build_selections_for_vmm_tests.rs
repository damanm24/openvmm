// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use anyhow::Ok;
use anyhow::anyhow;
use flowey::node::prelude::*;
use serde_json::Value;

flowey_request! {
    pub struct Request {
        pub archive_file: ReadVar<PathBuf>,
        pub target: target_lexicon::Triple,
        pub nextest_bin: ReadVar<PathBuf>,
        pub working_dir: ReadVar<PathBuf>,
        pub config_file: ReadVar<PathBuf>,
        pub nextest_profile: String,
        pub nextest_filter_expr: String,
        pub output_dir: ReadVar<PathBuf>,
        pub release: bool,
        pub build_selections: WriteVar<crate::_jobs::local_build_and_run_nextest_vmm_tests::BuildSelections>,
    }
}

new_simple_flow_node!(struct Node);

impl SimpleFlowNode for Node {
    type Request = Request;

    fn imports(ctx: &mut ImportCtx<'_>) {
        ctx.import::<flowey_lib_common::run_cargo_nextest_list::Node>();
        ctx.import::<flowey_lib_common::run_cargo_test::Node>();
    }

    fn process_request(request: Self::Request, ctx: &mut NodeCtx<'_>) -> anyhow::Result<()> {
        let Request {
            archive_file,
            target,
            nextest_bin,
            working_dir,
            config_file,
            nextest_profile,
            nextest_filter_expr,
            output_dir,
            release,
            build_selections,
        } = request;

        let nextest_list_cmd = ctx.reqv(|v| flowey_lib_common::run_cargo_nextest_list::Request {
            run_kind: flowey_lib_common::run_cargo_nextest_run::NextestRunKind::RunFromArchive {
                archive_file,
                target: Some(ReadVar::from_static(target.clone())),
                nextest_bin: Some(nextest_bin),
            },
            working_dir,
            config_file,
            nextest_profile: nextest_profile.as_str().to_owned(),
            nextest_filter_expr: Some(nextest_filter_expr),
            run_ignored: false,
            extra_env: None,
            output_dir,
            pre_run_deps: vec![],
            output_file: v,
        });

        let test_artifact_requirements = ctx.reqv(|v| flowey_lib_common::run_cargo_test::Request {
            packages:
                flowey_lib_common::run_cargo_nextest_run::build_params::TestPackages::Crates {
                    crates: vec!["vmm_tests".into()],
                },
            profile: match release {
                true => flowey_lib_common::run_cargo_build::CargoBuildProfile::Release,
                false => flowey_lib_common::run_cargo_build::CargoBuildProfile::Debug,
            },
            features: Default::default(),
            target,
            extra_args: Some(vec!["--list-required-artifacts=json".into()]),
            output: v,
        });

        // Analyze artifact requirements to determine what needs to be built
        // This happens after building the test binary but before building artifacts
        let computed_build_selections = ctx.emit_rust_stepv(
            "analyze artifact requirements and determine build selections",
            |ctx| {
                let nextest_list_cmd = nextest_list_cmd.claim(ctx);
                let test_artifact_requirements = test_artifact_requirements.claim(ctx);
                let nextest_filter_expr = nextest_filter_expr.clone();

                move |rt| {
                    let nextest_list_path = rt.read(nextest_list_cmd);
                    let requirements_json = rt.read(test_artifact_requirements);
                    let nextest_list_output = fs_err::read(nextest_list_path)?;
                    let v: Value = serde_json::from_slice(&nextest_list_output)?;
                    let rust_suites = v.get("rust-suites").and_then(Value::as_object).ok_or_else(|| anyhow!("missing rust-suites"))?;

                    let mut matched_names = Vec::new();

                    for (_suite_name, suite_val) in rust_suites {
                        if let Some(testcases) = suite_val.get("testcases").and_then(Value::as_object) {
                            for (test_name, test_val) in testcases {
                                let status = test_val.get("filter-match").and_then(|fm| fm.get("status")).and_then(Value::as_str);
                                if status == Some("matches") {
                                    matched_names.push(test_name.clone());
                                }
                            }
                        }
                    }

                    log::info!("Matched {} tests with filter: {}", matched_names.len(), nextest_filter_expr);

                    // Define a struct that matches the JSON output from petri
                    #[derive(serde::Deserialize, Debug)]
                    struct TestArtifactInfo {
                        name: String,
                        required: Vec<petri_artifacts_core::ErasedArtifactHandle>,
                        optional: Vec<petri_artifacts_core::ErasedArtifactHandle>,
                    }

                    // Parse artifact requirements
                    let mut all_required_artifacts = std::collections::BTreeSet::new();
                    let mut all_optional_artifacts = std::collections::BTreeSet::new();
                    let matched_names_set: std::collections::HashSet<_> = matched_names.iter().collect();

                    for line in requirements_json.lines() {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }

                        let test_infos: Vec<TestArtifactInfo> = serde_json::from_str(line)
                            .map_err(|e| {
                                anyhow::anyhow!(
                                    "Failed to parse test artifact requirements from line: {}\nError: {}",
                                    line,
                                    e
                                )
                            })?;

                        for test_info in &test_infos {
                            if !matched_names_set.contains(&test_info.name) {
                                continue;
                            }

                            for artifact in &test_info.required {
                                all_required_artifacts.insert(*artifact);
                            }

                            for artifact in &test_info.optional {
                                all_optional_artifacts.insert(*artifact);
                            }
                        }
                    }

                    log::info!(
                        "Unique required artifacts ({}): {:?}",
                        all_required_artifacts.len(),
                        all_required_artifacts
                    );
                    log::info!(
                        "Unique optional artifacts ({}): {:?}",
                        all_optional_artifacts.len(),
                        all_optional_artifacts
                    );

                    // Determine what needs to be built based on the artifact requirements
                    use petri_artifacts_common::artifacts as common;
                    use petri_artifacts_vmm_test::artifacts::*;

                    let mut computed_build = BuildSelections::default();

                    // Start with everything disabled
                    computed_build.openhcl = false;
                    computed_build.openvmm = false;
                    computed_build.pipette_windows = false;
                    computed_build.pipette_linux = false;
                    computed_build.prep_steps = false;
                    computed_build.guest_test_uefi = false;
                    computed_build.tmks = false;
                    computed_build.tmk_vmm_windows = false;
                    computed_build.tmk_vmm_linux = false;
                    computed_build.vmgstool = false;

                    // Check both required and optional artifacts to determine what to build
                    let all_artifacts: Vec<_> = all_required_artifacts.iter()
                        .chain(all_optional_artifacts.iter())
                        .copied()
                        .collect();

                    for id in all_artifacts {
                        // Pipette artifacts
                        if id == common::PIPETTE_WINDOWS_X64 || id == common::PIPETTE_WINDOWS_AARCH64 {
                            computed_build.pipette_windows = true;
                        }
                        if id == common::PIPETTE_LINUX_X64 || id == common::PIPETTE_LINUX_AARCH64 {
                            computed_build.pipette_linux = true;
                        }

                        // OpenVMM native executable
                        if id == OPENVMM_NATIVE {
                            computed_build.openvmm = true;
                        }

                        // OpenHCL IGVM artifacts
                        if id == openhcl_igvm::LATEST_STANDARD_X64
                            || id == openhcl_igvm::LATEST_STANDARD_DEV_KERNEL_X64
                            || id == openhcl_igvm::LATEST_CVM_X64
                            || id == openhcl_igvm::LATEST_LINUX_DIRECT_TEST_X64
                            || id == openhcl_igvm::LATEST_STANDARD_AARCH64
                            || id == openhcl_igvm::LATEST_STANDARD_DEV_KERNEL_AARCH64
                            || id == openhcl_igvm::RELEASE_25_05_STANDARD_X64
                            || id == openhcl_igvm::RELEASE_25_05_LINUX_DIRECT_X64
                            || id == openhcl_igvm::RELEASE_25_05_STANDARD_AARCH64
                            || id == openhcl_igvm::um_bin::LATEST_LINUX_DIRECT_TEST_X64
                            || id == openhcl_igvm::um_dbg::LATEST_LINUX_DIRECT_TEST_X64 {
                            computed_build.openhcl = true;
                        }

                        // Guest test UEFI disk
                        if id == test_vhd::GUEST_TEST_UEFI_X64 || id == test_vhd::GUEST_TEST_UEFI_AARCH64 {
                            computed_build.guest_test_uefi = true;
                        }

                        // Prepped test artifacts require prep steps
                        if id == test_vhd::GEN2_WINDOWS_DATA_CENTER_CORE2025_X64_PREPPED {
                            computed_build.prep_steps = true;
                        }

                        // TMK artifacts
                        if id == tmks::TMK_VMM_NATIVE {
                            computed_build.tmks = true;
                            // TMK_VMM_NATIVE could be windows or linux depending on host
                            // xtask-fmt allow-target-os oneoff-petri-native-test-deps
                            #[cfg(target_os = "windows")]
                            {
                                computed_build.tmk_vmm_windows = true;
                            }
                            // xtask-fmt allow-target-os oneoff-petri-native-test-deps
                            #[cfg(target_os = "linux")]
                            {
                                computed_build.tmk_vmm_linux = true;
                            }
                        }
                        if id == tmks::TMK_VMM_LINUX_X64_MUSL || id == tmks::TMK_VMM_LINUX_AARCH64_MUSL {
                            computed_build.tmks = true;
                            computed_build.tmk_vmm_linux = true;
                        }
                        if id == tmks::SIMPLE_TMK_X64 || id == tmks::SIMPLE_TMK_AARCH64 {
                            computed_build.tmks = true;
                        }

                        // Vmgstool
                        if id == VMGSTOOL_NATIVE {
                            computed_build.vmgstool = true;
                        }
                    }

                    log::info!("Computed build selections based on artifacts: {:#?}", computed_build);

                    Ok(computed_build)
                }
            },
        );

        Ok(())
    }
}
