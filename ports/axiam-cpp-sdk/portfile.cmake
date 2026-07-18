# vcpkg port for axiam-cpp-sdk.
#
# On a real release the SHA512 below is replaced with the archive hash for the
# tagged ref (e.g. via `vcpkg hash`). Kept as a placeholder here since the port is
# vendored in-repo alongside the sources it builds.
vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO ilpanich/axiam-cplusplus-sdk
    REF "v${VERSION}"
    SHA512 0
    HEAD_REF main
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DAXIAM_BUILD_TESTS=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(PACKAGE_NAME axiam-cpp-sdk CONFIG_PATH lib/cmake/axiam-cpp-sdk)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")
