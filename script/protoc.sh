find / -name "protoc"
find / -name "grpc_cpp_plugin"
sudo find / -name "protoc"
sudo find / -name "grpc_cpp_plugin"
protoc -I=../protos --cpp_out=../protos helloworld.proto
protoc --grpc_out=../protos --plugin=protoc-gen-grpc=/root/grpc_1.15.1_withoutgit/cmake/build/grpc_cpp_plugin helloworld.proto