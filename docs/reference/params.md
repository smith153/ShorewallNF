# params and preprocessing

Shorewall-style configs are **preprocessed** before they are parsed: variables from the
`params` file are substituted, and `?`-directives (`?if` conditionals, `?FORMAT`, `?SECTION`)
are resolved. ShorewallNF owns that stage as a pure text→text pass (`preprocessor.py`);
undefined variables and malformed directives fail fast with a `file:line` error rather than
being silently mis-parsed.

## The `params` file

`params` holds `NAME=value` variable definitions substituted into the other configuration
files. Each non-blank, non-comment line must be a bare assignment:

```
NAME=value
```

- `NAME` must be a valid identifier (a letter or `_`, then word characters).
- `value` is taken **literally**; surrounding whitespace is stripped.
- Blank lines and `#` comment lines are ignored.

### Forms that are rejected

These common shell forms are **not** supported and fail fast with a message naming the form,
rather than being mis-parsed:

| Rejected form | Why |
|---------------|-----|
| `export NAME=value` | The `export` prefix is unsupported — use `NAME=value`. |
| `NAME="value"` / `NAME='value'` | Quoted values are unsupported; the value is literal. |
| `NAME=value # comment` | Inline comments are unsupported (put comments on their own line). |
| A line with no `=`, or a non-identifier name | Not a well-formed `NAME=value` assignment. |

### Example

```
# params
MGMT_HOST=192.0.2.10
LAN_NET=198.51.100.0/24
SSH_PORT=22
```

## Variable substitution

In every other configuration file, `$NAME` or `${NAME}` is replaced by the variable's value:

```
#ACTION  SOURCE            DEST  PROTO  DEST PORT
ACCEPT   net:$MGMT_HOST    fw    tcp    $SSH_PORT
```

- Both `$NAME` and `${NAME}` are recognized. Names are identifiers; a bare `$` or `$5` is left
  untouched.
- A reference to a variable **not defined** in `params` is an error (`undefined variable $NAME`).
- A malformed `${...}` — unterminated, or an invalid name — is an error rather than passing
  through silently.
- There is no automatic firewall-zone variable (Shorewall's `$FW`): reference the
  firewall-type zone by the literal name it is given in the `zones` file, or define your own
  `params` variable for it.

## Preprocessing directives

Directives begin with `?` in the first column. Any token starting with `?` that is not one of
the directives below is rejected as an unknown directive (a typo or an unsupported Shorewall
directive) rather than parsed as data.

### `?if` / `?elsif` / `?else` / `?endif`

Conditional blocks keep only the lines in the active branch. Blocks may nest.

```
?if $ENABLE_IPV6
ACCEPT   net:2001:db8::/32   fw   tcp   22
?elsif $LEGACY
ACCEPT   net:198.51.100.0/24 fw   tcp   22
?else
DROP     net                 fw
?endif
```

Condition syntax (evaluated against `params` values):

- **Single token** — truthy when its resolved value is non-empty and not `"0"`.
- **`A == B`** / **`A != B`** — compare the two resolved values for (in)equality.
- In a condition, an **undefined** variable resolves to the empty string (falsy) — it is *not*
  an error here (unlike substitution).
- Anything richer — boolean operators (`&&`, `||`), or capability `__SYMBOL` checks — is
  unsupported and fails fast.

Misplaced or unbalanced directives are errors: `?elsif`/`?else`/`?endif` without a matching
`?if`, a second `?else`, an `?elsif` after `?else`, or an `?if` with no closing `?endif`.

### `?FORMAT n`

Selects a file's column layout for the rows that follow. The preprocessor checks only that the
argument is a **single positive integer**; which format numbers a given file accepts is that
file's concern (for example, the `interfaces` file uses `?FORMAT 1` with a `BROADCAST` column
and `?FORMAT 2` without it).

```
?FORMAT 2
```

### `?SECTION <NAME>`

Marks a section boundary the per-file parser acts on (for example, the `rules` file attaches
the current section to the filter rules that follow). The preprocessor checks only that
`?SECTION` carries a **single** name.

```
?SECTION NEW
```

## Processing order

`preprocess_file` runs, per file: resolve `?if` conditionals → validate `?FORMAT`/`?SECTION` →
reject unknown `?`-directives → substitute `$` variables. Conditionals are therefore evaluated
before substitution, and `?FORMAT`/`?SECTION` markers are **preserved** in the stream (they are
interpreted later by the per-file parser), not stripped.
