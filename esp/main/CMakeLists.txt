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
"lcd_elecrow7s3.c"
"sdmmc_crc_wrap.c"
"i2s.c"
"storage.c"
INCLUDE_DIRS "")

message(STATUS "Building for BOARD=${BOARD}")

if(BOARD STREQUAL "jc4880p443")
    add_definitions(-include ${CMAKE_CURRENT_SOURCE_DIR}/board_jc4880p443.h)
elseif(BOARD STREQUAL "elecrow7s3")
    add_definitions(-include ${CMAKE_CURRENT_SOURCE_DIR}/board_elecrow7s3.h)
else()
    # Default: jc3248w535
    add_definitions(-include ${CMAKE_CURRENT_SOURCE_DIR}/board_jc3248w535.h)
endif()

# Linker wrap for SPI SD CMD59 workaround (elecrow7s3 only)
if(BOARD STREQUAL "elecrow7s3")
    target_link_options(${COMPONENT_LIB} INTERFACE
        -Wl,--wrap=sdmmc_init_spi_crc
        -Wl,--undefined=__wrap_sdmmc_init_spi_crc)
endif()

add_definitions(-DI386_ENABLE_FPU)
add_definitions(-DUSE_FMOPL)

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
