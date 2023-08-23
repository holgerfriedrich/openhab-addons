for i in org.openhab.binding.* ; do echo $i; cd $i && mvn clean && mvn rewrite:run -Dohc.version=4.0.0 && mvn spotless:apply && mvn verify -Dohc.version=4.0.0 && cd -;  done               

