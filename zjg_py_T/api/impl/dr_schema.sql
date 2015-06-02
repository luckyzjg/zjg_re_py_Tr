-- MySQL dump 10.13  Distrib 5.5.37, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: DiamondRing
-- ------------------------------------------------------
-- Server version	5.5.37-0ubuntu0.13.10.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `NmapSession`
--

DROP TABLE IF EXISTS `NmapSession`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `NmapSession` (
  `Id` int(4) NOT NULL AUTO_INCREMENT,
  `SessionId` char(36) NOT NULL,
  `CreateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `EndTime` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `LogPath` text NOT NULL,
  `CmdLine` text NOT NULL,
  `Result` text,
  `Pid` int(4) DEFAULT '0',
  PRIMARY KEY (`Id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `NmapSession`
--

LOCK TABLES `NmapSession` WRITE;
/*!40000 ALTER TABLE `NmapSession` DISABLE KEYS */;
/*!40000 ALTER TABLE `NmapSession` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `OpenVASSession`
--

DROP TABLE IF EXISTS `OpenVASSession`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `OpenVASSession` (
  `Id` int(4) NOT NULL AUTO_INCREMENT,
  `SessionId` char(36) NOT NULL,
  `CreateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `EndTime` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `LogPath` text NOT NULL,
  `CmdLine` text NOT NULL,
  `Result` text,
  `TaskId` char(36) DEFAULT NULL,
  `ReportId` char(36) DEFAULT NULL,
  PRIMARY KEY (`Id`)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `OpenVASSession`
--

LOCK TABLES `OpenVASSession` WRITE;
/*!40000 ALTER TABLE `OpenVASSession` DISABLE KEYS */;
/*!40000 ALTER TABLE `OpenVASSession` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `ScanSession`
--

DROP TABLE IF EXISTS `ScanSession`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `ScanSession` (
  `Id` int(4) NOT NULL AUTO_INCREMENT,
  `SessionId` char(36) NOT NULL,
  `CreateTime` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `EndTime` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00',
  `TargetIP` char(64) NOT NULL,
  `ScanProfile` text NOT NULL,
  `Progress` int(4) NOT NULL DEFAULT '0',
  `ErrCode` int(4) NOT NULL DEFAULT '0',
  `Pid` int(4) DEFAULT '0',
  PRIMARY KEY (`Id`)
) ENGINE=InnoDB AUTO_INCREMENT=1 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `ScanSession`
--

LOCK TABLES `ScanSession` WRITE;
/*!40000 ALTER TABLE `ScanSession` DISABLE KEYS */;
/*!40000 ALTER TABLE `ScanSession` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2015-03-03  7:11:00
