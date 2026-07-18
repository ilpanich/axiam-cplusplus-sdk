from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.files import copy
import os


class AxiamCppSdkConan(ConanFile):
    name = "axiam-cpp-sdk"
    version = "1.0.0-alpha10"
    license = "Apache-2.0"
    url = "https://github.com/ilpanich/axiam-cplusplus-sdk"
    homepage = "https://github.com/ilpanich/axiam-cplusplus-sdk"
    description = (
        "AXIAM C++ SDK — authentication, authorization checks, JWKS "
        "verification and route guards (REST + mTLS)."
    )
    topics = ("axiam", "iam", "auth", "authorization", "mtls", "rest")

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "include/*",
        "src/*",
        "third_party/*",
        "LICENSE",
    )

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def requirements(self):
        self.requires("libcurl/[>=8.0.0]")
        self.requires("openssl/[>=3.0.0]")
        self.requires("nlohmann_json/[>=3.11.0]")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        CMakeDeps(self).generate()
        tc = CMakeToolchain(self)
        tc.variables["AXIAM_BUILD_TESTS"] = "OFF"
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        copy(self, "LICENSE", src=self.source_folder,
             dst=os.path.join(self.package_folder, "licenses"))

    def package_info(self):
        self.cpp_info.libs = ["axiam_cpp"]
        self.cpp_info.set_property("cmake_file_name", "axiam-cpp-sdk")
        self.cpp_info.set_property("cmake_target_name", "axiam::axiam_cpp")
