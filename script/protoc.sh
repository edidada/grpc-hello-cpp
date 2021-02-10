protoc -I=../protos --cpp_out=../protos helloworld.proto
protoc -I=../protos --grpc_out=../protos --plugin=protoc-gen-grpc=/Users/ibqo/vcpkg/packages/grpc_x64-osx/tools/grpc/grpc_cpp_plugin helloworld.proto
#protoc -I=../protos --grpc_out=../protos --plugin=protoc-gen-grpc=/home/travis/build/edidada/vcpkg/packages/grpc_x64-linux/tools/grpc/grpc_cpp_plugin helloworld.proto