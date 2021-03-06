#
# This file is auto-generated. DO NOT EDIT
# Generated by: autospec.py
#
Name     : libcaf
Version  : 0.14.6
Release  : 2
URL      : https://github.com/actor-framework/actor-framework/archive/0.14.6.tar.gz
Source0  : https://github.com/actor-framework/actor-framework/archive/0.14.6.tar.gz
Summary  : No detailed summary available
Group    : Development/Tools
License  : BSD-3-Clause
Requires: libcaf-lib
BuildRequires : cmake

%description
# CAF: C++ Actor Framework
CAF is an open source C++11 actor model implementation featuring
lightweight & fast actor implementations, pattern matching for messages,
network transparent messaging, and more.

%package dev
Summary: dev components for the libcaf package.
Group: Development
Requires: libcaf-lib
Provides: libcaf-devel

%description dev
dev components for the libcaf package.

%package lib
Summary: lib components for the libcaf package.
Group: Libraries

%description lib
lib components for the libcaf package.


%prep
%setup -q -n actor-framework-0.14.6

%build
export http_proxy=http://127.0.0.1:9/
export https_proxy=http://127.0.0.1:9/
export no_proxy=localhost,127.0.0.1,0.0.0.0
export LANG=C
export SOURCE_DATE_EPOCH=1522218551
mkdir clr-build
pushd clr-build
cmake .. -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS:BOOL=ON -DLIB_INSTALL_DIR:PATH=/usr/lib64 -DCMAKE_AR=/usr/bin/gcc-ar -DLIB_SUFFIX=64 -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_RANLIB=/usr/bin/gcc-ranlib -DCAF_NO_RIAC=yes -DCAF_NO_BENCHMARKS=yes -DCAF_NO_CASH=yes -DCAF_NO_NEXUS=yes -DCAF_NO_OPENCL=yes -DCAF_NO_CURL_EXAMPLES=yes -DCAF_NO_PROTOBUF_EXAMPLES=yes -DCAF_NO_QT_EXAMPLES=yes -DCAF_NO_EXAMPLES=yes -DCAF_NO_UNIT_TESTS=yes -DPTHREAD_LIBRARIES="-lpthread"
make  %{?_smp_mflags}
popd

%install
export SOURCE_DATE_EPOCH=1522218551
rm -rf %{buildroot}
pushd clr-build
%make_install
popd

%files
%defattr(-,root,root,-)

%files dev
%defattr(-,root,root,-)
/usr/include/caf/abstract_actor.hpp
/usr/include/caf/abstract_channel.hpp
/usr/include/caf/abstract_event_based_actor.hpp
/usr/include/caf/abstract_group.hpp
/usr/include/caf/abstract_uniform_type_info.hpp
/usr/include/caf/actor.hpp
/usr/include/caf/actor_addr.hpp
/usr/include/caf/actor_cast.hpp
/usr/include/caf/actor_companion.hpp
/usr/include/caf/actor_marker.hpp
/usr/include/caf/actor_namespace.hpp
/usr/include/caf/actor_ostream.hpp
/usr/include/caf/actor_pool.hpp
/usr/include/caf/actor_proxy.hpp
/usr/include/caf/all.hpp
/usr/include/caf/announce.hpp
/usr/include/caf/anything.hpp
/usr/include/caf/atom.hpp
/usr/include/caf/attachable.hpp
/usr/include/caf/await_all_actors_done.hpp
/usr/include/caf/behavior.hpp
/usr/include/caf/behavior_policy.hpp
/usr/include/caf/binary_deserializer.hpp
/usr/include/caf/binary_serializer.hpp
/usr/include/caf/blocking_actor.hpp
/usr/include/caf/callback.hpp
/usr/include/caf/channel.hpp
/usr/include/caf/check_typed_input.hpp
/usr/include/caf/config.hpp
/usr/include/caf/continue_helper.hpp
/usr/include/caf/default_attachable.hpp
/usr/include/caf/delegated.hpp
/usr/include/caf/deserializer.hpp
/usr/include/caf/detail/actor_registry.hpp
/usr/include/caf/detail/apply_args.hpp
/usr/include/caf/detail/arg_match_t.hpp
/usr/include/caf/detail/atom_val.hpp
/usr/include/caf/detail/behavior_impl.hpp
/usr/include/caf/detail/behavior_stack.hpp
/usr/include/caf/detail/boxed.hpp
/usr/include/caf/detail/build_config.hpp
/usr/include/caf/detail/cas_weak.hpp
/usr/include/caf/detail/comparable.hpp
/usr/include/caf/detail/concatenated_tuple.hpp
/usr/include/caf/detail/ctm.hpp
/usr/include/caf/detail/decorated_tuple.hpp
/usr/include/caf/detail/default_uniform_type_info.hpp
/usr/include/caf/detail/disablable_delete.hpp
/usr/include/caf/detail/disposer.hpp
/usr/include/caf/detail/double_ended_queue.hpp
/usr/include/caf/detail/embedded.hpp
/usr/include/caf/detail/functor_attachable.hpp
/usr/include/caf/detail/get_mac_addresses.hpp
/usr/include/caf/detail/get_process_id.hpp
/usr/include/caf/detail/get_root_uuid.hpp
/usr/include/caf/detail/group_manager.hpp
/usr/include/caf/detail/ieee_754.hpp
/usr/include/caf/detail/implicit_conversions.hpp
/usr/include/caf/detail/init_fun_factory.hpp
/usr/include/caf/detail/int_list.hpp
/usr/include/caf/detail/intrusive_partitioned_list.hpp
/usr/include/caf/detail/left_or_right.hpp
/usr/include/caf/detail/limited_vector.hpp
/usr/include/caf/detail/logging.hpp
/usr/include/caf/detail/match_case_builder.hpp
/usr/include/caf/detail/memory.hpp
/usr/include/caf/detail/memory_cache_flag_type.hpp
/usr/include/caf/detail/message_data.hpp
/usr/include/caf/detail/optional_message_visitor.hpp
/usr/include/caf/detail/pair_storage.hpp
/usr/include/caf/detail/parse_ini.hpp
/usr/include/caf/detail/pseudo_tuple.hpp
/usr/include/caf/detail/purge_refs.hpp
/usr/include/caf/detail/raw_access.hpp
/usr/include/caf/detail/ripemd_160.hpp
/usr/include/caf/detail/run_sub_unit_test.hpp
/usr/include/caf/detail/safe_equal.hpp
/usr/include/caf/detail/scope_guard.hpp
/usr/include/caf/detail/shared_spinlock.hpp
/usr/include/caf/detail/single_reader_queue.hpp
/usr/include/caf/detail/singleton_mixin.hpp
/usr/include/caf/detail/singletons.hpp
/usr/include/caf/detail/spawn_fwd.hpp
/usr/include/caf/detail/split_join.hpp
/usr/include/caf/detail/sync_request_bouncer.hpp
/usr/include/caf/detail/tail_argument_token.hpp
/usr/include/caf/detail/tbind.hpp
/usr/include/caf/detail/try_match.hpp
/usr/include/caf/detail/tuple_vals.hpp
/usr/include/caf/detail/tuple_zip.hpp
/usr/include/caf/detail/type_list.hpp
/usr/include/caf/detail/type_nr.hpp
/usr/include/caf/detail/type_pair.hpp
/usr/include/caf/detail/type_traits.hpp
/usr/include/caf/detail/typed_actor_util.hpp
/usr/include/caf/detail/unboxed.hpp
/usr/include/caf/detail/uniform_type_info_map.hpp
/usr/include/caf/detail/variant_data.hpp
/usr/include/caf/detail/wrapped.hpp
/usr/include/caf/duration.hpp
/usr/include/caf/either.hpp
/usr/include/caf/event_based_actor.hpp
/usr/include/caf/exception.hpp
/usr/include/caf/execution_unit.hpp
/usr/include/caf/exit_reason.hpp
/usr/include/caf/experimental/announce_actor_type.hpp
/usr/include/caf/experimental/whereis.hpp
/usr/include/caf/extend.hpp
/usr/include/caf/forwarding_actor_proxy.hpp
/usr/include/caf/from_string.hpp
/usr/include/caf/fwd.hpp
/usr/include/caf/group.hpp
/usr/include/caf/illegal_message_element.hpp
/usr/include/caf/infer_handle.hpp
/usr/include/caf/intrusive_ptr.hpp
/usr/include/caf/invoke_message_result.hpp
/usr/include/caf/io/abstract_broker.hpp
/usr/include/caf/io/accept_handle.hpp
/usr/include/caf/io/all.hpp
/usr/include/caf/io/basp.hpp
/usr/include/caf/io/basp_broker.hpp
/usr/include/caf/io/broker.hpp
/usr/include/caf/io/broker_servant.hpp
/usr/include/caf/io/connection_handle.hpp
/usr/include/caf/io/doorman.hpp
/usr/include/caf/io/experimental/typed_broker.hpp
/usr/include/caf/io/fwd.hpp
/usr/include/caf/io/handle.hpp
/usr/include/caf/io/hook.hpp
/usr/include/caf/io/max_msg_size.hpp
/usr/include/caf/io/middleman.hpp
/usr/include/caf/io/middleman_actor.hpp
/usr/include/caf/io/network/acceptor_manager.hpp
/usr/include/caf/io/network/asio_multiplexer.hpp
/usr/include/caf/io/network/asio_multiplexer_impl.hpp
/usr/include/caf/io/network/default_multiplexer.hpp
/usr/include/caf/io/network/interfaces.hpp
/usr/include/caf/io/network/manager.hpp
/usr/include/caf/io/network/multiplexer.hpp
/usr/include/caf/io/network/native_socket.hpp
/usr/include/caf/io/network/operation.hpp
/usr/include/caf/io/network/protocol.hpp
/usr/include/caf/io/network/stream_manager.hpp
/usr/include/caf/io/network/test_multiplexer.hpp
/usr/include/caf/io/publish.hpp
/usr/include/caf/io/publish_local_groups.hpp
/usr/include/caf/io/receive_policy.hpp
/usr/include/caf/io/remote_actor.hpp
/usr/include/caf/io/remote_group.hpp
/usr/include/caf/io/scribe.hpp
/usr/include/caf/io/set_middleman.hpp
/usr/include/caf/io/spawn_io.hpp
/usr/include/caf/io/system_messages.hpp
/usr/include/caf/io/unpublish.hpp
/usr/include/caf/local_actor.hpp
/usr/include/caf/locks.hpp
/usr/include/caf/mailbox_element.hpp
/usr/include/caf/make_counted.hpp
/usr/include/caf/match_case.hpp
/usr/include/caf/may_have_timeout.hpp
/usr/include/caf/memory_managed.hpp
/usr/include/caf/message.hpp
/usr/include/caf/message_builder.hpp
/usr/include/caf/message_handler.hpp
/usr/include/caf/message_id.hpp
/usr/include/caf/message_priority.hpp
/usr/include/caf/mixin/actor_widget.hpp
/usr/include/caf/mixin/sync_sender.hpp
/usr/include/caf/node_id.hpp
/usr/include/caf/none.hpp
/usr/include/caf/on.hpp
/usr/include/caf/optional.hpp
/usr/include/caf/parse_config.hpp
/usr/include/caf/policy/profiled.hpp
/usr/include/caf/policy/scheduler_policy.hpp
/usr/include/caf/policy/work_sharing.hpp
/usr/include/caf/policy/work_stealing.hpp
/usr/include/caf/primitive_variant.hpp
/usr/include/caf/ref_counted.hpp
/usr/include/caf/replies_to.hpp
/usr/include/caf/response_handle.hpp
/usr/include/caf/response_promise.hpp
/usr/include/caf/resumable.hpp
/usr/include/caf/sb_actor.hpp
/usr/include/caf/scheduler.hpp
/usr/include/caf/scheduler/abstract_coordinator.hpp
/usr/include/caf/scheduler/coordinator.hpp
/usr/include/caf/scheduler/detached_threads.hpp
/usr/include/caf/scheduler/profiled_coordinator.hpp
/usr/include/caf/scheduler/worker.hpp
/usr/include/caf/scoped_actor.hpp
/usr/include/caf/send.hpp
/usr/include/caf/serializer.hpp
/usr/include/caf/set_scheduler.hpp
/usr/include/caf/shutdown.hpp
/usr/include/caf/skip_message.hpp
/usr/include/caf/spawn.hpp
/usr/include/caf/spawn_fwd.hpp
/usr/include/caf/spawn_options.hpp
/usr/include/caf/stateful_actor.hpp
/usr/include/caf/static_visitor.hpp
/usr/include/caf/string_algorithms.hpp
/usr/include/caf/string_serialization.hpp
/usr/include/caf/system_messages.hpp
/usr/include/caf/test/unit_test.hpp
/usr/include/caf/test/unit_test_impl.hpp
/usr/include/caf/timeout_definition.hpp
/usr/include/caf/to_string.hpp
/usr/include/caf/type_name_access.hpp
/usr/include/caf/typed_actor.hpp
/usr/include/caf/typed_behavior.hpp
/usr/include/caf/typed_continue_helper.hpp
/usr/include/caf/typed_event_based_actor.hpp
/usr/include/caf/typed_response_promise.hpp
/usr/include/caf/uniform_type_info.hpp
/usr/include/caf/uniform_typeid.hpp
/usr/include/caf/unit.hpp
/usr/include/caf/variant.hpp
/usr/lib/libcaf_core.so
/usr/lib/libcaf_io.so

%files lib
%defattr(-,root,root,-)
/usr/lib/libcaf_core.so.0.14.6
/usr/lib/libcaf_io.so.0.14.6
