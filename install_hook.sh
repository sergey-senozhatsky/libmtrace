#!/bin/sh

MTRACE_PATH=./build/lib/

function remount_rootfs_rw
{
	return 0
	sync

	mount -o remount,rw /
	if [ $? != 0 ]; then
		echo "Can't remount rootfs"
		exit 6
	fi
}

function remount_rootfs_ro
{
	return 0
	sync

	mount -o remount,ro /
	if [ $? != 0 ]; then
		echo "Can't remount rootfs"
		exit 6
	fi
}

function install
{
	local path=$1

	if [ "z$path" == "z" ]; then
		echo "No application path was provided"
		exit 1
	fi

	if [ ! -e $path ]; then
		echo "Unknown application $path"
		exit 2
	fi

	if [ -e $path"_" ]; then
		echo "mtrace backup file already exists"
		exit 4
	fi

	if [ ! -e $MTRACE_PATH/libmtrace.so ]; then
		echo "No libmtrace.so file found at $MTRACE_PATH"
		exit 5
	fi

	remount_rootfs_rw

	mv $path $path"_"

cat << EOF > $path
#/bin/sh

MTRACE_LOG_DIR=/tmp/ MTRACE_ALLOC_MINWMARK=400 LD_PRELOAD=${MTRACE_PATH}/libmtrace.so ${path}_ "\$@"

EOF

	chmod +x $path

	remount_rootfs_ro

	return 0
}

function uninstall
{
	local path=$1

	if [ "z$path" == "z" ]; then
		echo "No application path was provided"
		exit 1
	fi

	if [ ! -e $path ]; then
		echo "Unknown application $path"
		exit 2
	fi

	if [ ! -e ${path}_ ]; then
		echo "No mtrace backup file was found"
		exit 4
	fi

	remount_rootfs_rw

	rm $path
	mv $path"_" $path

	remount_rootfs_ro

	return 0
}

if [ "z$1" == "zinstall" ]; then
	install $2
	exit $?
fi

if [ "z$1" == "zuninstall" ]; then
	uninstall $2
	exit $?
fi

echo "Usage example:"
echo "install_hook.sh install|uninstall /path/application"
exit 3
