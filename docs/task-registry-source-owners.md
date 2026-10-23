# Task and registry source owners

`task_registry_source_owners.TaskRegistrySourceOwners` derives observations
from the actual retained general task definition, original project registry
and two producer contracts. It provides fixed task and registry readers for
host composition. All four source selections and the implementation snapshot
come from the host; this API has no wire constructor or provider loader.

## Select and retain inputs

Use [RetainedContextSource](context-source-ownership.md) for each of the four
source files. Before opening the owner selection, obtain an implementation
snapshot with
`context_owner_implementation.observe_owner_implementation(package_root,
budget=budget)`, where the host selects the installed package directory.

The observer includes every regular package file, including nested modules
and runtime data, plus the bytes of the actual Python interpreter and its
runtime identity. It excludes generated `__pycache__` contents. Symlinks,
nonregular entries, hardlinked files, missing package initializers, changing
object identities and exceeded source, byte or entry budgets refuse. Limits
must explicitly accommodate the full package and interpreter.

The fixed owners independently observe their own package directory at each
use and compare the complete snapshot with the host's selection. Supplying a
snapshot of another directory or a different implementation does not appoint
a reader. The implementation content digest must also match both actual
producer contracts.

```python
from rigor_foundry.task_registry_source_owners import TaskRegistrySourceOwners

with TaskRegistrySourceOwners(
    task_source=retained_task,
    registry_source=retained_registry,
    task_contract=retained_task_contract,
    registry_contract=retained_registry_contract,
    implementation=selected_implementation,
    budget=budget,
) as owners:
    task_values = owners.observe(
        actor_id=selected_actor, root_id=selected_root, owner_class="task"
    )
    registry_values = owners.observe(
        actor_id=selected_actor, root_id=selected_root, owner_class="registry"
    )
    owners.verify(
        task_values,
        actor_id=selected_actor,
        root_id=selected_root,
        owner_class="task",
    )
```

The four retained sources are borrowed. Keep their own context managers open
through the owner context's closing check; the host remains responsible for
closing them. `close()` revalidates the source and code selection and is
idempotent. An owner that is closed, or whose selected inputs changed, cannot
emit or verify observations.

## Derive source-owned values

The task producer implementation is fixed to `builtin.task-definition.v1`;
the registry producer is fixed to `builtin.project-registry.v1`. Both
contracts must admit the actual selected registry format, identify distinct
owners and have identical selected root bindings.

Every root binding must refer to an actual registered project and its exact
owning group, with a canonical path inside that project's canonical path.
The task's project, group and all selected roots must agree. Affiliations and
retired aliases cannot replace canonical ownership.

| Owner | Available source-derived facts |
| --- | --- |
| Task | `task.id`, `task.revision`, `task.actor`, `task.project`, `task.group`, `task.root`, `task.lifecycle` |
| Registry | `project.id`, `project.group`, `project.lifecycle`, `project.target_kind`, `project.visibility`, `project.memory_state`, `registry.generation`, `registry.digest` |

Each result contains the exact contract's declared fact domain, original
source reference, independent subject digest, owning selection snapshot and
resulting `OwnerProof1`. Values come directly from the owning parsed source.
An identity-only task contract may declare an empty fact domain. Required
downstream domains remain the consumer's separate obligation.

`verify()` checks the proof binding and regenerates the actual observations
under the same owning entry. Rehashing an invented fact cannot make it agree
with its source. Another entry over equal files has a different selection
identity and cannot reuse that entry's proof.

## Host admission boundary

These readers verify task membership and registered source ownership.
Initiating user instructions, task events and claims require their own
existing authority checks. A task-selected root does not establish or reduce
the host's complete maintained inventory, language coverage or configured
scope. Contract root descriptors are checked against the registry; their
configured-scope digests alone do not prove actual complete configuration.

Complete package and interpreter observation does not qualify the enclosing
engine, loaded bytecode, all dependencies, toolchain, sandbox or revocation
custody. Those checks, inventory and fact owners, source-access authorization
and effect admission belong to the enclosing host. This API does not emit a
root admission or operation permit. Its retained-source requirements use
POSIX descriptor support; unsupported hosts refuse.
