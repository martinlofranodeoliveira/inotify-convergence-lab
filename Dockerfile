FROM gcc:14-bookworm
RUN apt-get update && apt-get install --yes --no-install-recommends libssl-dev make \
    && useradd --uid 1000 --create-home lab
WORKDIR /work
COPY --chown=1000:1000 . /work
USER 1000:1000
ENV HOME=/home/lab
CMD ["make", "test"]
