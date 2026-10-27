FROM python:3.12-slim-bookworm

# submissions are static x86-64 elfs; nothing else needed to run them
RUN useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin elfquine

WORKDIR /app
COPY validate.py server.py flag.txt /app/
RUN chmod 0444 /app/flag.txt \
    && chmod 0555 /app/validate.py /app/server.py

USER 10001:10001
EXPOSE 31903
ENV BIND_HOST=0.0.0.0 \
    BIND_PORT=31903 \
    BYTE_LIMIT=112 \
    RUN_TIMEOUT=2 \
    REQUIRE_X86_64=1

CMD ["python3", "/app/server.py"]
