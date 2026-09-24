# bash completion for ctf-id
# shellcheck disable=SC2207  # IFS is set to newline, so splitting is per line
_ctf_id(){
  local cur prev IFS=$'\n'
  cur="${COMP_WORDS[COMP_CWORD]}"; prev="${COMP_WORDS[COMP_CWORD-1]}"
  case "$prev" in
    -f) COMPREPLY=($(compgen -W $'flag\nCTF\npicoCTF\nHTB\nTHM\nDUCTF' -- "$cur")); return ;;
  esac
  if [[ "$cur" == -* ]]; then
    COMPREPLY=($(compgen -W $'-q\n-r\n--run\n-d\n--deep\n-f\n--doctor\n--update\n-V\n--version\n-h\n--help' -- "$cur"))
  else
    compopt -o filenames 2>/dev/null
    COMPREPLY=($(compgen -f -- "$cur"))
  fi
}
complete -F _ctf_id ctf-id
