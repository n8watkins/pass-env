#!/bin/sh
# A stand-in for pinentry-curses that answers GETPIN with $FAKE_PIN, or
# cancels when FAKE_PIN_CANCEL is set. Speaks just enough Assuan.
echo "OK Pleased to meet you"
while IFS= read -r line; do
	case "$line" in
		GETPIN)
			if [ -n "${FAKE_PIN_CANCEL:-}" ]; then echo "ERR 83886179 Operation cancelled <Pinentry>"
			else printf 'D %s\nOK\n' "${FAKE_PIN:-}"; fi ;;
		BYE) echo "OK closing connection"; exit 0 ;;
		*) echo OK ;;
	esac
done
