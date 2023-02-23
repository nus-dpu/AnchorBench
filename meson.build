project('SC_BENCHMARK', 'C',
	# Get version number from file.
	version: run_command(find_program('cat'),
		files('./VERSION'), check: true).stdout().strip(),
)

# project name
project_name = 'sc_benchmark'
project_name_abbreviation = 'sc'

# specified which application to use
app = 'sketch'
add_global_arguments('-DAPP_' + app.to_upper(), language: 'c')

# specified the sub directory to include more meson.build file
subdir('src/' + project_name_abbreviation + '_' + app)


# ==================== Third-party Library Detection ====================

# check whether doca exist
doca_path 				= '/opt/mellanox/doca'
doca_version			= ''
message('assume DOCA is located at ' + doca_path)
has_doca 				= false
doca_common_dep 		= dependency('doca-common', required: false)
doca_argp_dep 			= dependency('doca-argp', required: false)
doca_apsh_dep 			= dependency('doca-apsh', required: false)
doca_comm_channel_dep 	= dependency('doca-comm-channel', required: false)
doca_compress_dep 		= dependency('doca-compress', required: false)
doca_dma_dep 			= dependency('doca-dma', required: false)
doca_dpi_dep 			= dependency('doca-dpi', required: false)
doca_flow_dep 			= dependency('doca-flow', required: false)
doca_regex_dep 			= dependency('doca-regex', required: false)
doca_sha_dep 			= dependency('doca-sha', required: false)
doca_telemetry_dep 		= dependency('doca-telemetry', required: false)
if doca_common_dep.found() and doca_argp_dep.found() and doca_apsh_dep.found() \
		and doca_comm_channel_dep.found() and doca_compress_dep.found() \
		and doca_dma_dep.found() and doca_dpi_dep.found() \
		and doca_flow_dep.found() and doca_regex_dep.found() \
		and doca_sha_dep.found() and doca_telemetry_dep.found()
	# set doca as founded
	has_doca = true
	add_global_arguments('-DHAS_DOCA', language: 'c')

	# set doca version
	doca_version = run_command(
		find_program('cat'), files(doca_path + '/applications/VERSION'), check: true).stdout().strip()
	message('found DOCA ' + doca_version)

	# specified necessary doca resources according to application
	if app == 'sketch'
		add_global_arguments('-DNEED_DOCA_SHA', language: 'c')
		message('enabled DOCA SHA engine')
	endif
endif

#check whether cuda exist
cuda_path 	= '/usr/local/cuda'
message('assume CUDA is located at ' + cuda_path)
has_cuda 	= false
cuda_dep 	= dependency('cuda', version : '>=11', required: false)
if cuda_dep.found()
	has_cuda = true
	add_global_arguments('-DHAS_CUDA', language: 'c')
endif

# =======================================================================


# ==================== Specified All Dependent Library ==================

# basic dependencies
dep = []
dep += dependency('libdpdk', required: true)
dep += meson.get_compiler('c').find_library('pthread')
dep += meson.get_compiler('c').find_library('gmp')

# DOCA dependencies (optional)
if has_doca
	dep += doca_common_dep
	dep += doca_argp_dep
	dep += doca_apsh_dep
	dep += doca_comm_channel_dep
	dep += doca_compress_dep
	dep += doca_dma_dep
	dep += doca_dpi_dep
	dep += doca_flow_dep
	dep += doca_regex_dep
	dep += doca_sha_dep
	dep += doca_telemetry_dep
endif

# CUDA dependencies (optional)
if has_cuda
	dep += cuda_dep
endif

# =======================================================================



# ==================== Specified All Dependent Headers ==================

# scan all needed header files
glob = run_command('python3', files('./scan_include.py'), project_name_abbreviation, app, has_doca.to_string(), doca_path, doca_version, has_cuda.to_string(), cuda_path)
inc_dirs = include_directories(glob.stdout().strip().split('\n'))
# message(glob.stdout().strip().split('\n'))

# =======================================================================


# ====================== Specifed All Source Files ======================

# scan all needed source files
glob = run_command('python3', files('./scan_src.py'), app, has_doca.to_string(), doca_path, doca_version, has_cuda.to_string(), cuda_path)
sources = glob.stdout().strip().split('\n')
# message(sources)

# =======================================================================



# build executable
executable(project_name, sources,
	dependencies : dep,
	c_args: '-D_GNU_SOURCE',
	include_directories: inc_dirs,
	install: false
)