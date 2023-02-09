shell_folder=$(cd "$(dirname "$0")";pwd)

# Take the app name
read -p "App Name (lower case): " app_name
declare -u upper_app_name=$app_name


if [[ $app_name != "" ]]; then
  sed -i "s/subs_template/$app_name/g" $shell_folder/meson.build
  sed -i "s/subs_template/$app_name/g" $shell_folder/readme.md
  sed -i "s/subs_template/$app_name/g" $shell_folder/subs_template.h
  sed -i "s/subs_template/$app_name/g" $shell_folder/subs_template_dpdk.c
  sed -i "s/subs_template/$app_name/g" $shell_folder/subs_template_main.c
  sed -i "s/subs_template/$app_name/g" $shell_folder/subs_template_flow.c
  sed -i "s/subs_template/$app_name/g" $shell_folder/subs_template_utils.c
  sed -i "s/subs_template/$app_name/g" $shell_folder/subs_template_params.c

  sed -i "s/SUBS_TEMPLATE/$upper_app_name/g" $shell_folder/subs_template.h
  sed -i "s/SUBS_TEMPLATE/$upper_app_name/g" $shell_folder/subs_template_dpdk.c
  sed -i "s/SUBS_TEMPLATE/$upper_app_name/g" $shell_folder/subs_template_main.c
  sed -i "s/SUBS_TEMPLATE/$upper_app_name/g" $shell_folder/subs_template_flow.c
  sed -i "s/SUBS_TEMPLATE/$upper_app_name/g" $shell_folder/subs_template_utils.c
  sed -i "s/SUBS_TEMPLATE/$upper_app_name/g" $shell_folder/subs_template_params.c

  mv $shell_folder/subs_template_dpdk.c $shell_folder/${app_name}_dpdk.c
  mv $shell_folder/subs_template_main.c $shell_folder/${app_name}_main.c
  mv $shell_folder/subs_template_flow.c $shell_folder/${app_name}_flow.c
  mv $shell_folder/subs_template_utils.c $shell_folder/${app_name}_utils.c
  mv $shell_folder/subs_template_params.c $shell_folder/${app_name}_params.c
  mv $shell_folder/subs_template.h $shell_folder/${app_name}.h
fi



