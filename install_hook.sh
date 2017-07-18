#!/bin/sh

MTRACE_PATH=./build/lib/

function remount_rootfs_rw
{
	if [ $1 -eq 0 ]; then
		return 0
	fi

	sync

	mount -o remount,rw /
	if [ $? != 0 ]; then
		echo "Can't remount rootfs"
		exit 6
	fi
}

function remount_rootfs_ro
{
	if [ $1 -eq 0 ]; then
		return 0
	fi

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
	local remount=$2

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

	remount_rootfs_rw $remount

	mv $path $path"_"

cat << EOF > $path
#/bin/sh

MTRACE_LOG_DIR=/tmp/ MTRACE_ALLOC_MINWMARK=400 LD_PRELOAD=${MTRACE_PATH}/libmtrace.so ${path}_ "\$@"

EOF

	chmod +x $path

	remount_rootfs_ro $remount

	return 0
}

function uninstall
{
	local path=$1
	local remount=$2

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

	remount_rootfs_rw $remount

	rm $path
	mv $path"_" $path

	remount_rootfs_ro $remount

	return 0
}

function main
{
	if [ "z$1" == "zinstall" -o "z$1" == "zrinstall" ]; then
		local remount=0

		if [ "z$1" == "zrinstall" ]; then
			remount=1
		fi

		install $2 $remount
		exit $?
	fi

	if [ "z$1" == "zuninstall" -o "z$1" == "zruninstall" ]; then
		local remount=0

		if [ "z$1" == "zruninstall" ]; then
			remount=1
		fi
		uninstall $2 $remount
		exit $?
	fi
}

main $1 $2

echo "Usage example:"
echo "install_hook.sh install|uninstall /path/application"
echo "                rinstall|runinstall - to force remount of FS in rw mode"
exit 3
