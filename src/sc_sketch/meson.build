# ========== basic macro ==========
# specified the execute role
# [1] client / server
role = 'server'
add_global_arguments('-DROLE_' + role.to_upper(), language: 'c')

# ========== application specific macro ==========
# specified the execute mode
# [1] throughput / [2] accuracy / [3] latency
mode = 'latency'
add_global_arguments('-DMODE_' + mode.to_upper(), language: 'c')

# sketch type to used:
# [1] cm / [2] 
skecth_type = 'cm'
add_global_arguments('-DSKETCH_TYPE_' + skecth_type.to_upper(), language: 'c')