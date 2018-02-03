@ptr_cell_t@
identifier func;
identifier cell;
@@
func(...) {
cell_t* cell;
<...
(
- cell->command
+ cell->header.command
|
- cell->circ_id
+ cell->header.circ_id
)
...>
}

@ptr_cell_t_param@
identifier func;
identifier cell;
@@
func(..., cell_t* cell, ...) {
<...
(
- cell->command
+ cell->header.command
|
- cell->circ_id
+ cell->header.circ_id
)
...>
}

@struct_cell_t@
identifier func;
identifier cell;
@@
func(...) {
cell_t cell;
<...
(
- cell.command
+ cell.header.command
|
- cell.circ_id
+ cell.header.circ_id
)
...>
}

@struct_cell_t_param@
identifier func;
identifier cell;
@@
func(..., cell_t cell, ...) {
<...
(
- cell.command
+ cell.header.command
|
- cell.circ_id
+ cell.header.circ_id
)
...>
}

@ptr_var_cell_t@
identifier func;
identifier cell;
@@
func(...) {
var_cell_t* cell;
<...
(
- var_cell->command
+ var_cell->header.command
|
- var_cell->circ_id
+ var_cell->header.circ_id
)
...>
}

@ptr_var_cell_t_param@
identifier func;
identifier cell;
@@
func(..., var_cell_t* cell, ...) {
<...
(
- var_cell->command
+ var_cell->header.command
|
- var_cell->circ_id
+ var_cell->header.circ_id
)
...>
}

@struct_var_cell_t@
identifier func;
identifier cell;
@@
func(...) {
var_cell_t cell;
<...
(
- T.command
+ T.header.command
|
- T.circ_id
+ T.header.circ_id
)
...>
}

@struct_var_cell_t_param@
identifier func;
identifier cell;
@@
func(..., var_cell_t cell, ...) {
<...
(
- T.command
+ T.header.command
|
- T.circ_id
+ T.header.circ_id
)
...>
}
