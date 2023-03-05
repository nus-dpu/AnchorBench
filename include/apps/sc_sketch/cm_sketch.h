#ifndef _SC_CM_SKETCH_H_
#define _SC_CM_SKETCH_H_

int __cm_update(const char* key, struct sc_config *sc_config);
int __cm_query(const char* key, void *result, struct sc_config *sc_config);
int __cm_clean(struct sc_config *sc_config);
int __cm_record(const char* key, struct sc_config *sc_config);
int __cm_evaluate(struct sc_config *sc_config);

#endif

