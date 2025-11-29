idf_component_register(SRCS "esp_main.c"
"../../adlib.c"
"../../fmopl.c"
"../../fpu.c"
"../../i386.c"
"../../i8042.c"
"../../i8254.c"
"../../i8259.c"
"../../ide.c"
"../../ini.c"
"../../pc.c"
"../../misc.c"
"../../pci.c"
"../../vga.c"
"../../ne2000.c"
"../../i8257.c"
"../../sb16.c"
"../../pcspk.c"
"wifi.c"
"lcd_axs15231b.c"
"lcd_st7701.c"
"i2s.c"
"storage.c"
INCLUDE_DIRS "")

# XXX
if(CONFIG_IDF_TARGET_ESP32P4)
    add_definitions(-include ${CMAKE_CURRENT_SOURCE_DIR}/board_jc4880p433.h)
else()
    add_definitions(-include ${CMAKE_CURRENT_SOURCE_DIR}/board_jc3248w535.h)
endif()


set_source_files_properties("../../adlib.c" PROPERTIES COMPILE_FLAGS "-Wno-all")
set_source_files_properties("../../fmopl.c" PROPERTIES COMPILE_FLAGS "-Wno-all -fsingle-precision-constant")
set_source_files_properties("../../fpu.c" PROPERTIES COMPILE_FLAGS "-Wno-all")
set_source_files_properties("../../i386.c" PROPERTIES COMPILE_FLAGS "-Wno-all -O3")
set_source_files_properties("../../i8042.c" PROPERTIES COMPILE_FLAGS "-Wno-all")
set_source_files_properties("../../vga.c" PROPERTIES COMPILE_FLAGS "-Wno-all -O3")
set_source_files_properties("../../pc.c" PROPERTIES COMPILE_FLAGS "-Wno-all -O3")
set_source_files_properties("../../ne2000.c" PROPERTIES COMPILE_FLAGS "-Wno-all")
set_source_files_properties("../../sb16.c" PROPERTIES COMPILE_FLAGS "-Wno-all")
set_source_files_properties("../../i8257.c" PROPERTIES COMPILE_FLAGS "-Wno-all")

if(NOT EXISTS "../../fmopl.inc")
    message(FATAL_ERROR "Please run `make prepare` first")
endif()
