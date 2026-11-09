#!/bin/sh
# A stand-in for pinentry-curses that answers GETPIN with $FAKE_PIN, or
# cancels when FAKE_PIN_CANCEL is set. Speaks just enough Assuan.
# FAKE_PIN_SEQ names a file of answers, one per line, used up in order (each
# prompt is a new pinentry process). FAKE_PIN_LOG records the texts it was
# asked to show (SETDESC, SETERROR), never the answers.
echo "OK Pleased to meet you"
while IFS= read -r line; do
	case "$line" in
		GETPIN)
			if [ -n "${FAKE_PIN_CANCEL:-}" ]; then echo "ERR 83886179 Operation cancelled <Pinentry>"
			elif [ -n "${FAKE_PIN_SEQ:-}" ]; then
				pin=$(head -n 1 "$FAKE_PIN_SEQ")
				tail -n +2 "$FAKE_PIN_SEQ" > "$FAKE_PIN_SEQ.rest" && mv "$FAKE_PIN_SEQ.rest" "$FAKE_PIN_SEQ"
				printf 'D %s\nOK\n' "$pin"
			else printf 'D %s\nOK\n' "${FAKE_PIN:-}"; fi ;;
		SETDESC*|SETERROR*) [ -n "${FAKE_PIN_LOG:-}" ] && echo "$line" >> "$FAKE_PIN_LOG"; echo OK ;;
		BYE) echo "OK closing connection"; exit 0 ;;
		*) echo OK ;;
	esac
done
