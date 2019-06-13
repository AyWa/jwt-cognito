FROM golang:1.11

LABEL "name"="go unit test"
LABEL "maintainer"="Marc Hurabielle"
LABEL "version"="1.0.0"

LABEL "com.github.actions.icon"="code"
LABEL "com.github.actions.color"="green-dark"
LABEL "com.github.actions.name"="go unit test"
LABEL "com.github.actions.description"="Will run unit test"

COPY test.sh /test.sh
ENTRYPOINT ["/test.sh"]