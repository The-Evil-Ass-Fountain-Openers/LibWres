add_executable(libwrestest
    main.cpp
)

target_link_libraries(libwrestest wres)
include(GNUInstallDirs)
#install(TARGETS libwrestest
#    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
#    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
#)

