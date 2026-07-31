// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests deferred host commit for WHP guest RAM mappings.

#![cfg(all(windows, target_arch = "x86_64"))]

use sparse_mmap::SparseMapping;

const MAP_RWX: whp::abi::WHV_MAP_GPA_RANGE_FLAGS = whp::abi::WHV_MAP_GPA_RANGE_FLAGS(
    whp::abi::WHvMapGpaRangeFlagRead.0
        | whp::abi::WHvMapGpaRangeFlagWrite.0
        | whp::abi::WHvMapGpaRangeFlagExecute.0,
);

#[test]
fn reserved_host_memory_can_be_committed_after_guest_fault() {
    const PAGE_SIZE: usize = 4096;
    const DATA_GPA: u64 = 0x2000;

    let code = SparseMapping::new(PAGE_SIZE).unwrap();
    code.alloc(0, PAGE_SIZE).unwrap();
    // Reset-vector code: mov byte ptr [bx], al; hlt.
    code.write_at(0xff0, b"\x88\x07\xf4").unwrap();

    let data = SparseMapping::new(64 * 1024).unwrap();
    data.reserve(0, data.len()).unwrap();

    let mut config = whp::PartitionConfig::new().unwrap();
    config
        .set_property(whp::PartitionProperty::ProcessorCount(1))
        .unwrap();
    let partition = config.create().unwrap();
    partition.create_vp(0).create().unwrap();

    // SAFETY: both sparse mappings remain alive and stable until after the
    // partition is dropped, and each mapped range lies within its mapping.
    #[expect(unsafe_code, reason = "WHP mapping lifetime is upheld by this test")]
    unsafe {
        partition
            .map_range(None, code.as_ptr().cast(), PAGE_SIZE, 0xff000, MAP_RWX)
            .unwrap();
        partition
            .map_range(None, data.as_ptr().cast(), data.len(), DATA_GPA, MAP_RWX)
            .unwrap();
    }

    let vp = partition.vp(0);
    whp::set_registers!(
        vp,
        [
            (whp::Register64::Rax, 0x5a),
            (whp::Register64::Rbx, DATA_GPA),
            (whp::Register64::Rflags, 0x2)
        ]
    )
    .unwrap();

    let mut runner = vp.runner();
    let exit = runner.run().unwrap();
    let whp::ExitReason::MemoryAccess(access) = exit.reason else {
        panic!("expected memory-access exit, got {:?}", exit.reason);
    };
    assert_eq!(access.Gpa, DATA_GPA);

    data.commit(0, PAGE_SIZE).unwrap();
    partition
        .populate_ranges(
            &[whp::abi::WHV_MEMORY_RANGE_ENTRY {
                GuestAddress: DATA_GPA,
                SizeInBytes: PAGE_SIZE as u64,
            }],
            whp::abi::WHvMemoryAccessWrite,
            Default::default(),
        )
        .unwrap();

    let exit = runner.run().unwrap();
    assert!(matches!(exit.reason, whp::ExitReason::Halt));

    let mut actual = [0];
    data.read_at(0, &mut actual).unwrap();
    assert_eq!(actual[0], 0x5a);
}
