IMG_NAME=metaextractor
IMG_VERSION=latest
CT_NAME=${IMG_NAME}_ct
MAINTAINER=to_be_set
CT_FILE=Containerfile
LOCAL_PATH=to_be_set

test:
	echo ${IMG_NAME}
	echo ${IMG_VERSION}
	echo ${CT_NAME}
	echo ${MAINTAINER}
	echo ${CT_FILE}
	pwd

build:
	podman build -f ${CT_FILE} -t ${MAINTAINER}/${IMG_NAME}:${IMG_VERSION}

run-it:
	podman run -it --rm -v ${LOCAL_PATH}/data:/tmp/data --name metaextractor-ct localhost/to_be_set/metaextractor:latest
