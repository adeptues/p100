openhab uses osgi+karaf

osgi is the seventh circle of dependency hell.

it does not work like normal java development where simply addding the maven coords to
the pom includes the lib and dependency resolution pulls in that deps sub dependdencies

*every* dependecy must be listed in karafs features.xml along with sub deps with
the format `mvn:commons-codec/commons-codec/1.15`

then if your lib does not come osgified you have to wrap it with 
`wrap:mvn:com.adeptues/p100/0.0.1-SNAPSHOT`

when building the addon and installing the jar file no dependencies are installed
when putting the jar in the /addons folder they are only installed when the
karaf runtime looks at the features.xml and pulls them in during normal deployment
however you can build a .kar karaf archive which includes the dependency information
but the openhabteam does not like this


Message: org.apache.karaf.features.internal.util.MultiException: Error:
means you need to wrap in the features.xml as above 