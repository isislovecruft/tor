/* cell_created2v.h -- generated by Trunnel v1.5.2.
 * https://gitweb.torproject.org/trunnel.git
 * You probably shouldn't edit this file.
 */
#ifndef TRUNNEL_CELL_CREATED2V_H
#define TRUNNEL_CELL_CREATED2V_H

#include <stdint.h>
#include "trunnel.h"

#if !defined(TRUNNEL_OPAQUE) && !defined(TRUNNEL_OPAQUE_CREATE2V_CELL_BODY)
struct create2v_cell_body_st {
  uint16_t htype;
  uint16_t hlen;
  TRUNNEL_DYNARRAY_HEAD(, uint8_t) hdata;
  TRUNNEL_DYNARRAY_HEAD(, uint8_t) ignored;
  uint8_t trunnel_error_code_;
};
#endif
typedef struct create2v_cell_body_st create2v_cell_body_t;
#if !defined(TRUNNEL_OPAQUE) && !defined(TRUNNEL_OPAQUE_CREATED2V_CELL_BODY)
struct created2v_cell_body_st {
  uint16_t hlen;
  TRUNNEL_DYNARRAY_HEAD(, uint8_t) hdata;
  TRUNNEL_DYNARRAY_HEAD(, uint8_t) ignored;
  uint8_t trunnel_error_code_;
};
#endif
typedef struct created2v_cell_body_st created2v_cell_body_t;
/** Return a newly allocated create2v_cell_body with all elements set
 * to zero.
 */
create2v_cell_body_t *create2v_cell_body_new(void);
/** Release all storage held by the create2v_cell_body in 'victim'.
 * (Do nothing if 'victim' is NULL.)
 */
void create2v_cell_body_free(create2v_cell_body_t *victim);
/** Try to parse a create2v_cell_body from the buffer in 'input',
 * using up to 'len_in' bytes from the input buffer. On success,
 * return the number of bytes consumed and set *output to the newly
 * allocated create2v_cell_body_t. On failure, return -2 if the input
 * appears truncated, and -1 if the input is otherwise invalid.
 */
ssize_t create2v_cell_body_parse(create2v_cell_body_t **output, const uint8_t *input, const size_t len_in);
/** Return the number of bytes we expect to need to encode the
 * create2v_cell_body in 'obj'. On failure, return a negative value.
 * Note that this value may be an overestimate, and can even be an
 * underestimate for certain unencodeable objects.
 */
ssize_t create2v_cell_body_encoded_len(const create2v_cell_body_t *obj);
/** Try to encode the create2v_cell_body from 'input' into the buffer
 * at 'output', using up to 'avail' bytes of the output buffer. On
 * success, return the number of bytes used. On failure, return -2 if
 * the buffer was not long enough, and -1 if the input was invalid.
 */
ssize_t create2v_cell_body_encode(uint8_t *output, size_t avail, const create2v_cell_body_t *input);
/** Check whether the internal state of the create2v_cell_body in
 * 'obj' is consistent. Return NULL if it is, and a short message if
 * it is not.
 */
const char *create2v_cell_body_check(const create2v_cell_body_t *obj);
/** Clear any errors that were set on the object 'obj' by its setter
 * functions. Return true iff errors were cleared.
 */
int create2v_cell_body_clear_errors(create2v_cell_body_t *obj);
/** Return the value of the htype field of the create2v_cell_body_t in
 * 'inp'
 */
uint16_t create2v_cell_body_get_htype(const create2v_cell_body_t *inp);
/** Set the value of the htype field of the create2v_cell_body_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int create2v_cell_body_set_htype(create2v_cell_body_t *inp, uint16_t val);
/** Return the value of the hlen field of the create2v_cell_body_t in
 * 'inp'
 */
uint16_t create2v_cell_body_get_hlen(const create2v_cell_body_t *inp);
/** Set the value of the hlen field of the create2v_cell_body_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int create2v_cell_body_set_hlen(create2v_cell_body_t *inp, uint16_t val);
/** Return the length of the dynamic array holding the hdata field of
 * the create2v_cell_body_t in 'inp'.
 */
size_t create2v_cell_body_getlen_hdata(const create2v_cell_body_t *inp);
/** Return the element at position 'idx' of the dynamic array field
 * hdata of the create2v_cell_body_t in 'inp'.
 */
uint8_t create2v_cell_body_get_hdata(create2v_cell_body_t *inp, size_t idx);
/** As create2v_cell_body_get_hdata, but take and return a const
 * pointer
 */
uint8_t create2v_cell_body_getconst_hdata(const create2v_cell_body_t *inp, size_t idx);
/** Change the element at position 'idx' of the dynamic array field
 * hdata of the create2v_cell_body_t in 'inp', so that it will hold
 * the value 'elt'.
 */
int create2v_cell_body_set_hdata(create2v_cell_body_t *inp, size_t idx, uint8_t elt);
/** Append a new element 'elt' to the dynamic array field hdata of the
 * create2v_cell_body_t in 'inp'.
 */
int create2v_cell_body_add_hdata(create2v_cell_body_t *inp, uint8_t elt);
/** Return a pointer to the variable-length array field hdata of
 * 'inp'.
 */
uint8_t * create2v_cell_body_getarray_hdata(create2v_cell_body_t *inp);
/** As create2v_cell_body_get_hdata, but take and return a const
 * pointer
 */
const uint8_t  * create2v_cell_body_getconstarray_hdata(const create2v_cell_body_t *inp);
/** Change the length of the variable-length array field hdata of
 * 'inp' to 'newlen'.Fill extra elements with 0. Return 0 on success;
 * return -1 and set the error code on 'inp' on failure.
 */
int create2v_cell_body_setlen_hdata(create2v_cell_body_t *inp, size_t newlen);
/** Return the length of the dynamic array holding the ignored field
 * of the create2v_cell_body_t in 'inp'.
 */
size_t create2v_cell_body_getlen_ignored(const create2v_cell_body_t *inp);
/** Return the element at position 'idx' of the dynamic array field
 * ignored of the create2v_cell_body_t in 'inp'.
 */
uint8_t create2v_cell_body_get_ignored(create2v_cell_body_t *inp, size_t idx);
/** As create2v_cell_body_get_ignored, but take and return a const
 * pointer
 */
uint8_t create2v_cell_body_getconst_ignored(const create2v_cell_body_t *inp, size_t idx);
/** Change the element at position 'idx' of the dynamic array field
 * ignored of the create2v_cell_body_t in 'inp', so that it will hold
 * the value 'elt'.
 */
int create2v_cell_body_set_ignored(create2v_cell_body_t *inp, size_t idx, uint8_t elt);
/** Append a new element 'elt' to the dynamic array field ignored of
 * the create2v_cell_body_t in 'inp'.
 */
int create2v_cell_body_add_ignored(create2v_cell_body_t *inp, uint8_t elt);
/** Return a pointer to the variable-length array field ignored of
 * 'inp'.
 */
uint8_t * create2v_cell_body_getarray_ignored(create2v_cell_body_t *inp);
/** As create2v_cell_body_get_ignored, but take and return a const
 * pointer
 */
const uint8_t  * create2v_cell_body_getconstarray_ignored(const create2v_cell_body_t *inp);
/** Change the length of the variable-length array field ignored of
 * 'inp' to 'newlen'.Fill extra elements with 0. Return 0 on success;
 * return -1 and set the error code on 'inp' on failure.
 */
int create2v_cell_body_setlen_ignored(create2v_cell_body_t *inp, size_t newlen);
/** Return a newly allocated created2v_cell_body with all elements set
 * to zero.
 */
created2v_cell_body_t *created2v_cell_body_new(void);
/** Release all storage held by the created2v_cell_body in 'victim'.
 * (Do nothing if 'victim' is NULL.)
 */
void created2v_cell_body_free(created2v_cell_body_t *victim);
/** Try to parse a created2v_cell_body from the buffer in 'input',
 * using up to 'len_in' bytes from the input buffer. On success,
 * return the number of bytes consumed and set *output to the newly
 * allocated created2v_cell_body_t. On failure, return -2 if the input
 * appears truncated, and -1 if the input is otherwise invalid.
 */
ssize_t created2v_cell_body_parse(created2v_cell_body_t **output, const uint8_t *input, const size_t len_in);
/** Return the number of bytes we expect to need to encode the
 * created2v_cell_body in 'obj'. On failure, return a negative value.
 * Note that this value may be an overestimate, and can even be an
 * underestimate for certain unencodeable objects.
 */
ssize_t created2v_cell_body_encoded_len(const created2v_cell_body_t *obj);
/** Try to encode the created2v_cell_body from 'input' into the buffer
 * at 'output', using up to 'avail' bytes of the output buffer. On
 * success, return the number of bytes used. On failure, return -2 if
 * the buffer was not long enough, and -1 if the input was invalid.
 */
ssize_t created2v_cell_body_encode(uint8_t *output, size_t avail, const created2v_cell_body_t *input);
/** Check whether the internal state of the created2v_cell_body in
 * 'obj' is consistent. Return NULL if it is, and a short message if
 * it is not.
 */
const char *created2v_cell_body_check(const created2v_cell_body_t *obj);
/** Clear any errors that were set on the object 'obj' by its setter
 * functions. Return true iff errors were cleared.
 */
int created2v_cell_body_clear_errors(created2v_cell_body_t *obj);
/** Return the value of the hlen field of the created2v_cell_body_t in
 * 'inp'
 */
uint16_t created2v_cell_body_get_hlen(const created2v_cell_body_t *inp);
/** Set the value of the hlen field of the created2v_cell_body_t in
 * 'inp' to 'val'. Return 0 on success; return -1 and set the error
 * code on 'inp' on failure.
 */
int created2v_cell_body_set_hlen(created2v_cell_body_t *inp, uint16_t val);
/** Return the length of the dynamic array holding the hdata field of
 * the created2v_cell_body_t in 'inp'.
 */
size_t created2v_cell_body_getlen_hdata(const created2v_cell_body_t *inp);
/** Return the element at position 'idx' of the dynamic array field
 * hdata of the created2v_cell_body_t in 'inp'.
 */
uint8_t created2v_cell_body_get_hdata(created2v_cell_body_t *inp, size_t idx);
/** As created2v_cell_body_get_hdata, but take and return a const
 * pointer
 */
uint8_t created2v_cell_body_getconst_hdata(const created2v_cell_body_t *inp, size_t idx);
/** Change the element at position 'idx' of the dynamic array field
 * hdata of the created2v_cell_body_t in 'inp', so that it will hold
 * the value 'elt'.
 */
int created2v_cell_body_set_hdata(created2v_cell_body_t *inp, size_t idx, uint8_t elt);
/** Append a new element 'elt' to the dynamic array field hdata of the
 * created2v_cell_body_t in 'inp'.
 */
int created2v_cell_body_add_hdata(created2v_cell_body_t *inp, uint8_t elt);
/** Return a pointer to the variable-length array field hdata of
 * 'inp'.
 */
uint8_t * created2v_cell_body_getarray_hdata(created2v_cell_body_t *inp);
/** As created2v_cell_body_get_hdata, but take and return a const
 * pointer
 */
const uint8_t  * created2v_cell_body_getconstarray_hdata(const created2v_cell_body_t *inp);
/** Change the length of the variable-length array field hdata of
 * 'inp' to 'newlen'.Fill extra elements with 0. Return 0 on success;
 * return -1 and set the error code on 'inp' on failure.
 */
int created2v_cell_body_setlen_hdata(created2v_cell_body_t *inp, size_t newlen);
/** Return the length of the dynamic array holding the ignored field
 * of the created2v_cell_body_t in 'inp'.
 */
size_t created2v_cell_body_getlen_ignored(const created2v_cell_body_t *inp);
/** Return the element at position 'idx' of the dynamic array field
 * ignored of the created2v_cell_body_t in 'inp'.
 */
uint8_t created2v_cell_body_get_ignored(created2v_cell_body_t *inp, size_t idx);
/** As created2v_cell_body_get_ignored, but take and return a const
 * pointer
 */
uint8_t created2v_cell_body_getconst_ignored(const created2v_cell_body_t *inp, size_t idx);
/** Change the element at position 'idx' of the dynamic array field
 * ignored of the created2v_cell_body_t in 'inp', so that it will hold
 * the value 'elt'.
 */
int created2v_cell_body_set_ignored(created2v_cell_body_t *inp, size_t idx, uint8_t elt);
/** Append a new element 'elt' to the dynamic array field ignored of
 * the created2v_cell_body_t in 'inp'.
 */
int created2v_cell_body_add_ignored(created2v_cell_body_t *inp, uint8_t elt);
/** Return a pointer to the variable-length array field ignored of
 * 'inp'.
 */
uint8_t * created2v_cell_body_getarray_ignored(created2v_cell_body_t *inp);
/** As created2v_cell_body_get_ignored, but take and return a const
 * pointer
 */
const uint8_t  * created2v_cell_body_getconstarray_ignored(const created2v_cell_body_t *inp);
/** Change the length of the variable-length array field ignored of
 * 'inp' to 'newlen'.Fill extra elements with 0. Return 0 on success;
 * return -1 and set the error code on 'inp' on failure.
 */
int created2v_cell_body_setlen_ignored(created2v_cell_body_t *inp, size_t newlen);


#endif
