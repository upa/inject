
RYU=/usr/local/bin/ryu-manager
INJECT=/var/local/inject/inject.py
INJECTLOG=/var/log/inject.log

PATH=/bin:/usr/bin:/usr/local/bin


if [ `whoami` != "root" ]; then
	echo "run as root"
	exit
fi

start() {
	echo "start inject"
	$RYU $INJECT >> $INJECTLOG 2>&1 &
}

stop() {
	echo "kill inject"
	killall ryu-manager
}

case $1 in
	start)
		start
		;;
	stop)
		stop
		;;
	restart)
		stop
		start
		;;
	*)
		echo "usage $0 {start|stop|restart}"
		;;
esac
