
thread_dep = dependency('threads')
pcap_dep = dependency('pcap', version : '>=1.0')

executable('echo', 'echo.cpp', dependencies: thread_dep, link_with: enso_lib,
           include_directories: inc)
executable('echo_event', 'echo_event.cpp', dependencies: thread_dep,
           link_with: enso_lib, include_directories: inc)
executable('echo_prefetch', 'echo_prefetch.cpp', dependencies: thread_dep,
           link_with: enso_lib, include_directories: inc)
executable('echo_copy', 'echo_copy.cpp', dependencies: thread_dep,
           link_with: enso_lib, include_directories: inc)
executable('ensogen', 'ensogen.cpp', dependencies: [thread_dep, pcap_dep],
           link_with: enso_lib, include_directories: inc)
executable('capture', 'capture.cpp', dependencies: [thread_dep, pcap_dep],
           link_with: enso_lib, include_directories: inc)
