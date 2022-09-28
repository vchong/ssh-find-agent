#!/bin/bash

# Copyright (C) 2011 by Wayne Walker <wwalker@solid-constructs.com>
#
# Released under one of the versions of the MIT License.
#
# Copyright (C) 2011 by Wayne Walker <wwalker@solid-constructs.com>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# temp dir. Defaults to /tmp
_TMPDIR="${TMPDIR:-/tmp}"

# Allow users to override _TMPDIR without requiring them to change
# their shell's TMPDIR when sourcing the script. This is useful in the
# context of custom shells (e.g. nix shells) where TMPDIR in the custom
# shell can differ from the system's TMPDIR, but we want the script to
# use the system's TMPDIR when sourced.
if [[ -e "$_TMPDIR_OVERRIDE" ]]; then
  _TMPDIR="$_TMPDIR_OVERRIDE"
fi

if ! command -v 'timeout' &>/dev/null; then
  cat <<EOF >&2
ssh-find-agent.sh: 'timeout' command could not be found:
  Please install 'coreutils' via your system's package manager
EOF
fi

sfa_die() {
  sfa_debug_print "$@"
  exit 1
}

sfa_debug_print() {
  if [[ $_DEBUG -gt 0 ]]; then
    # shellcheck disable=SC2059
    printf "$@" 1>&2
  fi
}

sfa_find_all_agent_sockets() {
  _ssh_agent_sockets=$(
    find "$_TMPDIR" -maxdepth 2 -type s  -name agent.\*              2>/dev/null | grep '/ssh-.*/agent.*';
    find "$_TMPDIR" -maxdepth 2 -type s  -name S.gpg-agent.ssh       2>/dev/null | grep '/gpg-.*/S.gpg-agent.ssh';
    find "$_TMPDIR" -maxdepth 2 -type s  -name ssh                   2>/dev/null | grep '/keyring-.*/ssh$';
    find "$_TMPDIR" -maxdepth 2 -type s -regex '.*/ssh-.*/agent..*$' 2>/dev/null
  )
  sfa_debug_print "$_ssh_agent_sockets"
}

sfa_test_agent_socket() {
  local socket=$1
  SSH_AUTH_SOCK=$socket timeout 0.4 ssh-add -l 2>/dev/null >/dev/null
  result=$?

  sfa_debug_print $result

  case $result in
    0)
      # contactible and has keys loaded
      _key_count=$(SSH_AUTH_SOCK=$socket ssh-add -l 2>&1 | grep -c 'error fetching identities for protocol 1: agent refused operation')
      ;;
    1)
      # contactible but no keys loaded
      _key_count=0
      ;;
    2|124)
      # socket is dead, delete it
      rm -rf "${socket%/*}" 1>/dev/null 2>&1
      ;;
    125|126|127)
      printf 'timeout returned <%s>\n' "$result" 1>&2
      ;;
    *)
      printf 'Unknown failure timeout returned <%s>\n' "$result" 1>&2
  esac

  case $result in
    0|1)
      _live_agent_list+=("$_key_count:$socket")
      return 0
  esac

  return 1
}


sfa_verify_sockets() {
  for i in $_ssh_agent_sockets; do
    sfa_test_agent_socket "$i"
  done
}

function fingerprints() {
  local file="$1"
  while read -r l; do
    [[ -n "$l" && ${l##\#} = "$l" ]] && ssh-keygen -l -f /dev/stdin <<<"$l"
  done <"$file"
}

sfa_print_choose_menu() {
  _show_identity=0
  if [ "$1" = "-i" ]; then
    _show_identity=1
  fi
  sfa_find_all_agent_sockets
  sfa_verify_sockets
  sfa_debug_print '<%s>\n' "${_live_agent_list[@]}"

  # shellcheck disable=SC2207
  IFS=$'\n' _sorted_live_agent_list=($(sort -u <<<"${_live_agent_list[*]}"))
  unset IFS
  
  sfa_debug_print "SORTED:\n"
  sfa_debug_print '    <%s>\n' "${_sorted_live_agent_list[@]}"

  local i=0
  local sock

    for a in "${_sorted_live_agent_list[@]}"; do
      i=$((i + 1))
      sock=${a/*:/}
      _live_agent_sock_list[$i]=$sock

      printf '#%i)\n' "$i"
      printf '    export SSH_AUTH_SOCK=%s\n' "$sock"
      if [[ $_show_identity -gt 0 ]]; then
        # Get all the forwarded keys for this agent, parse them and print them
      SSH_AUTH_SOCK=$sock ssh-add -l 2>&1 | \
        grep -v 'error fetching identities for protocol 1: agent refused operation' | \
        while IFS= read -r key; do
          parts=("$key")
          key_size="${parts[0]}"
          fingerprint="${parts[1]}"
          remote_name="${parts[2]}"
          key_type="${parts[3]}"
          printf '        %s %s\t%s\t%s\n' "$key_size" "$key_type" "$remote_name" "$fingerprint"
        done
      else
        printf "%s\n" "${_sorted_live_agent_list[@]}"
      fi
    done
}

set_ssh_agent_socket() {
  if [[ "$1" = "-c" ]] || [[ "$1" = "--choose" ]]; then
    sfa_print_choose_menu -i

    if (( 0 == ${#_live_agent_list[@]} )); then
      sfa_die 'No agents found.\n'
      return 1
    fi

    read -p "Choose (1-${#_live_agent_sock_list[@]})? " -r choice
    if [ -n "$choice" ]; then
      n=$((choice - 1))
      if [ -z "${_live_agent_sock_list[$n]}" ]; then
        sfa_die 'Invalid choice.\n'
      fi
      printf 'Setting export SSH_AUTH_SOCK=%s\n' "${_live_agent_sock_list[$n]}"
      export SSH_AUTH_SOCK=${_live_agent_sock_list[$n]}
    fi
  else
    # Choose the first available
    SOCK=$(sfa_print_choose_menu | tail -n 1 | awk -F: '{print $1}')
    if [ -z "$SOCK" ]; then
      return 1
    fi
    export SSH_AUTH_SOCK=$SOCK
  fi

  # set agent pid
  if [ -n "$SSH_AUTH_SOCK" ]; then
    export SSH_AGENT_PID=$(($(basename "$SSH_AUTH_SOCK" | cut -d. -f2) + 1))
  fi

  return 0
}

_sfa_usage() {
  printf 'ssh-find-agent <[-c|--choose|-a|--auto|-h|--help]>\n'
}

# Renamed for https://github.com/wwalker/ssh-find-agent/issues/12
ssh_find_agent() {
  declare -a _live_agent_list
  declare -a _live_agent_sock_list
  declare -a _sorted_live_agent_list
  _ssh_agent_sockets=()
  _live_agent_list=()
  _live_agent_sock_list=()

  case $1 in
    -c | --choose)
      set_ssh_agent_socket -c
      return $?
      ;;
    -a | --auto)
      set_ssh_agent_socket
      return $?
      ;;
    "")
      sfa_print_choose_menu -i
      return 0
      ;;
    *)
      _sfa_usage
      ;;
  esac
}

# Original function name is still supported.
# https://github.com/wwalker/ssh-find-agent/issues/12 points out that I
# should use ssh_find_agent() for best compatibility.
ssh-find-agent() {
  ssh_find_agent "$@"
}
