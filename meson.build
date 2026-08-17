# SPDX-License-Identifier: Apache-2.0
project('passewall', 'c',
  version : '0.1.0',
  license : 'Apache-2.0',
  meson_version : '>= 0.59.0',
  default_options : [
    'c_std=c11',
    'warning_level=2',
    'buildtype=debugoptimized',
  ],
)

cc = meson.get_compiler('c')
add_project_arguments('-D_GNU_SOURCE', language : 'c')

# ---- core dependencies -----------------------------------------------------
threads_dep = dependency('threads')
nfq_dep     = dependency('libnetfilter_queue',
  required : true,
  not_found_message : 'Install libnetfilter-queue development files ' +
                      '(libnetfilter-queue-dev / libnetfilter_queue).')

core_sources = files(
  'src/main.c',
  'src/log.c',
  'src/queue.c',
  'src/net.c',
  'src/tcp.c',
  'src/http.c',
  'src/tls.c',
  'src/dns.c',
  'src/iptables.c',
)

deps = [threads_dep, nfq_dep]
c_args = []
gui_sources = []
gui_resources = []

# ---- optional GUI ----------------------------------------------------------
build_gui = get_option('gui')
if build_gui
  gtk_dep = dependency('gtk4',      required : true)
  adw_dep = dependency('libadwaita-1', required : true)
  gio_dep = dependency('gio-2.0',   required : true)

  deps += [gtk_dep, adw_dep, gio_dep]
  c_args += ['-DHAVE_GUI=1']
  gui_sources = files(
    'src/gui/window.c',
    'src/gui/tray.c',
    'src/gui/autostart.c',
  )

  # Bundle the GitHub / Discord symbolic icons as a GResource so they are
  # available by icon name (github-symbolic / discord-symbolic) at runtime.
  gnome = import('gnome')
  gui_resources = gnome.compile_resources(
    'passewall-resources',
    'data/passewall.gresource.xml',
    source_dir : 'data/icons',
    c_name : 'passewall',
  )

  message('GUI enabled (GTK4 + libadwaita)')
else
  message('GUI disabled: building headless binary only')
endif

inc = include_directories('src')

executable('passewall',
  core_sources + gui_sources + gui_resources,
  dependencies : deps,
  c_args : c_args,
  include_directories : inc,
  install : true,
)

# ---- data ------------------------------------------------------------------
datadir = get_option('datadir')

install_data('data/io.github.taigalinux.Passewall.desktop',
  install_dir : join_paths(datadir, 'applications'))

install_data('data/io.github.taigalinux.Passewall.metainfo.xml',
  install_dir : join_paths(datadir, 'metainfo'))

install_data('assets/passewall.svg',
  install_dir : join_paths(datadir, 'icons/hicolor/scalable/apps'),
  rename : 'io.github.taigalinux.Passewall.svg')

meson.add_install_script('sh', '-c',
  'echo "Passewall installed. Run as root: sudo passewall (GUI) or sudo passewall --no-gui"')
