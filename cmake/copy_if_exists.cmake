if(NOT DEFINED SRC)
  message(FATAL_ERROR "SRC is required")
endif()

if(NOT DEFINED DST_DIR)
  message(FATAL_ERROR "DST_DIR is required")
endif()

if(EXISTS "${SRC}")
  get_filename_component(_name "${SRC}" NAME)
  file(COPY_FILE "${SRC}" "${DST_DIR}/${_name}" ONLY_IF_DIFFERENT)
endif()
