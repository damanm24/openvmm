# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Exercises overlapping virtio-fs DAX mappings from a Linux guest.

Linux maps a DAX file in 2 MiB windows. Reading a window first maps it
read-only; a later write to the same window sends FUSE_SETUPMAPPING again for
the same window offset (`fuse_upgrade_dax_mapping`), so the host must replace
an existing mapping in place. Each scenario below drives that path and checks
the data seen through the DAX window.

Usage: virtiofs_dax_overlap.py <dax mount> <result dir>
"""

import mmap
import os
import sys
import time

DAX = sys.argv[1]
RESULT_DIR = sys.argv[2]
WINDOW = 2 << 20
PAGE = 4096
ZERO_PAGE = bytes(PAGE)


def log(msg):
    print(msg, flush=True)


def create(name, size):
    """Creates a section-backed file of `size` bytes and returns an open fd."""
    path = os.path.join(DAX, name)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    # SectionFs creates the backing section on the first fallocate.
    os.posix_fallocate(fd, 0, size)
    return path, fd


def expect(actual, expected, what):
    if actual != expected:
        raise AssertionError(
            f"{what}: expected {expected[:16]!r}..., got {actual[:16]!r}..."
        )


def read_then_write():
    """Read each window (read-only mapping), then write it (remap in place)."""
    _, fd = create("read_then_write", 4 * WINDOW)
    for w in range(4):
        expect(os.pread(fd, PAGE, w * WINDOW), ZERO_PAGE, f"initial window {w}")
    for w in range(4):
        os.pwrite(fd, bytes([0x10 + w]) * PAGE, w * WINDOW + PAGE)
    for w in range(4):
        expect(os.pread(fd, PAGE, w * WINDOW), ZERO_PAGE, f"untouched page {w}")
        expect(
            os.pread(fd, PAGE, w * WINDOW + PAGE),
            bytes([0x10 + w]) * PAGE,
            f"written page {w}",
        )
    os.close(fd)
    log("read_then_write: ok")


def mmap_read_then_write():
    """Same as `read_then_write`, but through read and write page faults."""
    _, fd = create("mmap_read_then_write", 2 * WINDOW)
    m = mmap.mmap(fd, 2 * WINDOW, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
    expect(m[0:PAGE], ZERO_PAGE, "window 0 read fault")
    expect(m[WINDOW : WINDOW + PAGE], ZERO_PAGE, "window 1 read fault")
    m[100:105] = b"hello"
    m[WINDOW + 7 : WINDOW + 12] = b"world"
    m.flush()
    expect(m[100:105], b"hello", "window 0 after write fault")
    m.close()
    expect(os.pread(fd, 5, 100), b"hello", "window 0 via read")
    expect(os.pread(fd, 5, WINDOW + 7), b"world", "window 1 via read")
    os.close(fd)
    log("mmap_read_then_write: ok")


def remap_after_eviction():
    """Drop the guest's mappings, then map and remap a new file.

    Evicting the inodes makes the guest remove their DAX mappings (and
    SectionFs drops the sections, since nothing holds them open any more), so
    the new file's windows are mapped into ranges that were just unmapped.
    """
    os.sync()
    with open("/proc/sys/vm/drop_caches", "w") as f:
        f.write("3")
    _, fd = create("after_eviction", 4 * WINDOW)
    for w in range(4):
        expect(os.pread(fd, PAGE, w * WINDOW), ZERO_PAGE, f"window {w} after eviction")
    for w in range(4):
        os.pwrite(fd, bytes([0x30 + w]) * PAGE, w * WINDOW + 2 * PAGE)
    for w in range(4):
        expect(
            os.pread(fd, PAGE, w * WINDOW + 2 * PAGE),
            bytes([0x30 + w]) * PAGE,
            f"page {w} after eviction",
        )
    os.close(fd)
    log("remap_after_eviction: ok")


def concurrent_reader(iterations):
    """Remap a window while another process keeps reading it.

    The reader only checks pages the writer never changes, so it must always
    see zeros: on Windows the host briefly unmaps the window while replacing
    it, and a read that lands in that gap must be retried rather than
    completed against unmapped memory.
    """
    reads = 0
    for i in range(iterations):
        path, fd = create(f"race{i}", WINDOW)
        r, w = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(r)
            ok = True
            try:
                rfd = os.open(path, os.O_RDONLY)
                m = mmap.mmap(rfd, WINDOW, mmap.MAP_SHARED, mmap.PROT_READ)
                ok = m[0:PAGE] == ZERO_PAGE
                os.write(w, b"r")
                n = 0
                deadline = time.monotonic() + 0.2
                while ok and time.monotonic() < deadline:
                    for off in range(0, WINDOW - PAGE, 16 * PAGE):
                        if m[off : off + PAGE] != ZERO_PAGE:
                            ok = False
                            break
                    n += 1
                os.write(w, n.to_bytes(8, "little"))
            except BaseException as e:  # noqa: BLE001
                print(f"reader {i} failed: {e!r}", file=sys.stderr, flush=True)
                ok = False
            os._exit(0 if ok else 1)
        os.close(w)
        if os.read(r, 1) != b"r":
            raise AssertionError(f"reader {i} did not start")
        time.sleep(0.02)
        # The window is mapped read-only for the reader, so this write makes
        # the guest remap it writable in place while the reader is running.
        os.pwrite(fd, b"\x5a" * PAGE, WINDOW - PAGE)
        _, status = os.waitpid(pid, 0)
        count = os.read(r, 8)
        os.close(r)
        if os.waitstatus_to_exitcode(status) != 0:
            raise AssertionError(f"reader {i} saw unexpected data or failed")
        reads += int.from_bytes(count, "little") if len(count) == 8 else 0
        expect(os.pread(fd, PAGE, WINDOW - PAGE), b"\x5a" * PAGE, f"race {i} write")
        os.close(fd)
    log(f"concurrent_reader: ok ({iterations} remaps, {reads} reader passes)")


def main():
    read_then_write()
    mmap_read_then_write()
    remap_after_eviction()
    concurrent_reader(int(os.environ.get("DAX_RACE_ITERATIONS", "64")))
    with open(os.path.join(RESULT_DIR, "result.txt"), "w") as f:
        f.write("PASS\n")
    log("PASS")


if __name__ == "__main__":
    main()
