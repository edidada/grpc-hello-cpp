gRPC C++ Hello World Tutorial
==============================

# Setup

`vckpg install grpc`
/usr/local/bin/protoc


/Users/ibqo/vcpkg/packages/grpc_x64-osx/tools/grpc/grpc_cpp_plugin


```cmake
    find_package(gRPC CONFIG REQUIRED)
    # Note: 7 target(s) were omitted.
    target_link_libraries(main PRIVATE gRPC::gpr gRPC::grpc gRPC::grpc++ gRPC::grpc++_alts)
    find_package(modules CONFIG REQUIRED)
    target_link_libraries(main PRIVATE re2::re2 c-ares::cares)
```

* Build protobuf from source to install header files, libs & camke files https://github.com/google/protobuf/blob/master/src/README.md
* Then use Clion to open project

# References

* gRPC C++ Quick Start: https://grpc.io/docs/quickstart/cpp.html
* protobuf install: https://github.com/google/protobuf/blob/master/src/README.md
* Clion Protobuf plugin: https://plugins.jetbrains.com/plugin/8277-protobuf-support

### grpc
version
        1.15.1
        
### pb
version
3.6.1

如何使用pb生成cpp文件？
protoc 

protoc -I=protos --cpp_out=protos helloworld.proto
protoc --grpc_out=. --plugin=protoc-gen-grpc=/root/grpc_1.15.1_withoutgit/cmake/build/grpc_cpp_plugin protos/helloworld.proto
生成grpc和protobuf的代码


```cmake
FOREACH(FIL ${protobuf_files})

    GET_FILENAME_COMPONENT(FIL_WE ${FIL} NAME_WE)

    string(REGEX REPLACE ".+/(.+)\\..*" "\\1" FILE_NAME ${FIL})
    string(REGEX REPLACE "(.+)\\${FILE_NAME}.*" "\\1" FILE_PATH ${FIL})

    string(REGEX MATCH "(/mediapipe/framework.*|/mediapipe/util.*|/mediapipe/calculators/internal/)" OUT_PATH ${FILE_PATH})

    set(PROTO_SRCS "${CMAKE_CURRENT_BINARY_DIR}${OUT_PATH}${FIL_WE}.pb.cc")
    set(PROTO_HDRS "${CMAKE_CURRENT_BINARY_DIR}${OUT_PATH}${FIL_WE}.pb.h")

    EXECUTE_PROCESS(
            COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ${PROTO_FLAGS} --cpp_out=${PROTO_META_BASE_DIR} ${FIL}
    )
    message("Copying " ${PROTO_SRCS} " to " ${FILE_PATH})

    file(COPY ${PROTO_SRCS} DESTINATION ${FILE_PATH})
    file(COPY ${PROTO_HDRS} DESTINATION ${FILE_PATH})

ENDFOREACH()
```
