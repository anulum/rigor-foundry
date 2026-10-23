<!--
SPDX-License-Identifier: Apache-2.0
Apache License 2.0; see LICENSE.
© Concepts 1996–2026 Miroslav Šotek. All rights reserved.
© Code 2020–2026 Miroslav Šotek. All rights reserved.
ORCID: 0009-0009-3560-0851
Contact: www.anulum.li | protoscience@anulum.li
RigorFoundry — Git command provenance and resource bounds
-->
# Git command provenance and resource bounds

`rigor_foundry.git_provenance.GitRunner` runs Git through an inspected,
descriptor-pinned executable. Its trust policy selects executable roots and a
supported version interval. Each command checks executable content and filesystem
identity before and after execution. Ambient `PATH`, global and system Git
configuration, replacement objects, optional locks and interactive credentials do
not select the command. Reserved command configuration disables repository hooks
and filesystem monitors.

Executable inspection opens the leaf with nonblocking I/O before checking its
actual descriptor type. A FIFO cannot block that regular-file check.

The public `run(cwd, *arguments, check=True, timeout_seconds=30,
output_limit=8388608)` method uses the shared streaming process runner. Its output
ceiling counts standard output and standard error together. It is checked during
reading; an over-limit result raises rather than returning a truncated inventory.
Exactly the permitted number of bytes succeeds. Version discovery has a separate
4096-byte ceiling. Timeout and output limits must be positive integers; boolean
values are refused.

The command deadline covers output collection and waiting for the leader after
its pipes close. On timeout or output exhaustion the runner terminates the
process group and reaps its leader. No shell interprets the arguments. Standard
output and standard error remain bytes, including binary Git objects and NUL
separators. `check=False` returns a bounded nonzero result; `check=True` raises on
a nonzero exit without including the command's output in the exception message.

```python
from pathlib import Path

from rigor_foundry.git_provenance import GitRunner

runner = GitRunner()
result = runner.run(
    Path.cwd(), "ls-files", "--stage", "-z", output_limit=1024 * 1024
)
index_bytes = result.stdout
```

Callers supply an output budget appropriate to their admitted inventory and
parse the complete result. These limits do not establish inventory completeness,
source-access permission, snapshot atomicity, policy admission or native-effect
authority. Descriptor execution requires an available `/proc/self/fd` or
`/dev/fd`; the process-group implementation requires POSIX process facilities.
