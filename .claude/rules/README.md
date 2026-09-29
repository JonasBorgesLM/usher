# Generic rules

Empty on purpose, and this file explains why rather than leaving a bare
directory.

Path-scoped rules load automatically when a matching file is touched, so they
are the right place for an invariant stated **close to the code it constrains**.
That makes them inherently specific: a rule general enough to apply to every
project belongs in `~/.claude/CLAUDE.md`, where it is loaded once instead of
being copied into every repository.

So the generic set is empty by construction. Rules arrive here only when one has
been true across three or more projects **and** its reason survives being
generalised — which, so far, none has: the candidates all lose their incident
when the project name is removed, and a rule without its incident is a slogan.

Stack rules live under `kit/stacks/` in the foundation repository (this
paragraph deliberately does not link there: once copied into a project, the
relative path would not resolve). Write new ones with `plan-rule-author`.

**The filter for any rule, here or in a stack:** it states an invariant that can
be violated *without a compile error and without a failing test*. A rule
restating what the compiler enforces is noise.
