# Throwaway image: the target hugo binary + the external content-format converters
# (asciidoctor / docutils rst2html / pandoc) needed to validate HUGO-025/026/027.
# These are the binaries an operator would install to "support AsciiDoc/RST/Pandoc content".
FROM cvehunterlab_hugo_app:latest
USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends asciidoctor docutils pandoc \
    && apt-get clean
USER hugo:hugo
