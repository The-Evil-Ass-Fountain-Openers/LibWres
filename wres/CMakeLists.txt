add_library(wres SHARED
    macros.h
    wresutil.h
    wresutil.cpp
    winlibrary.h
    winlibrary.cpp
    winresource.h
    winresource.cpp
    ../common/common.h
    ../common/error.cpp
    ../common/error.h
    ../common/intutil.cpp
    ../common/intutil.h
    ../common/io-utils.cpp
    ../common/io-utils.h
    ../common/llist.cpp
    ../common/llist.h
    ../common/strbuf.cpp
    ../common/strbuf.h
    ../common/string-utils.cpp
    ../common/string-utils.h
    ../common/win32-endian.cpp
    ../common/win32-endian.h
    ../common/win32.h
)
set(wres_HEADERS
    macros.h
    wresutil.h
    winlibrary.h
    winresource.h
    ../common/common.h
    ../common/error.h
    ../common/intutil.h
    ../common/io-utils.h
    ../common/llist.h
    ../common/strbuf.h
    ../common/string-utils.h
    ../common/win32-endian.h
    ../common/win32.h
)

include(GNUInstallDirs)
install(FILES ${wres_HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wres)
install(TARGETS wres
    EXPORT LibWres-targets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(EXPORT LibWres-targets DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibWres)
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/Config.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/LibWresConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibWres
)
install(FILES
          "${CMAKE_CURRENT_BINARY_DIR}/LibWresConfig.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/LibWres
)
#target_link_libraries(wres common)
