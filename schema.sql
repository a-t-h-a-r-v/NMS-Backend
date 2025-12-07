CREATE TABLE IF NOT EXISTS 'network_monitor';
USE network_monitor;
/*M!999999\- enable the sandbox mode */
-- MariaDB dump 10.19-11.8.3-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: network_monitor
-- ------------------------------------------------------
-- Server version	11.8.3-MariaDB-0+deb13u1 from Debian

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*M!100616 SET @OLD_NOTE_VERBOSITY=@@NOTE_VERBOSITY, NOTE_VERBOSITY=0 */;

--
-- Table structure for table `alerts`
--

DROP TABLE IF EXISTS `alerts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `alerts` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) DEFAULT NULL,
  `severity` varchar(20) DEFAULT NULL,
  `message` text DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `alerts_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=7 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `device_health`
--

DROP TABLE IF EXISTS `device_health`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `device_health` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) NOT NULL,
  `uptime_seconds` bigint(20) DEFAULT NULL,
  `load_1min` float DEFAULT NULL,
  `load_5min` float DEFAULT NULL,
  `load_15min` float DEFAULT NULL,
  `ram_total` bigint(20) DEFAULT NULL,
  `ram_used` bigint(20) DEFAULT NULL,
  `swap_total` bigint(20) DEFAULT NULL,
  `swap_used` bigint(20) DEFAULT NULL,
  `collected_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `device_health_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=934 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `devices`
--

DROP TABLE IF EXISTS `devices`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `devices` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `hostname` varchar(255) NOT NULL,
  `ip_address` varchar(45) NOT NULL,
  `community_string` varchar(255) DEFAULT 'public',
  `snmp_version` varchar(10) DEFAULT '2c',
  `check_interval` int(11) DEFAULT 60,
  `sys_descr` text DEFAULT NULL,
  `sys_object_id` varchar(255) DEFAULT NULL,
  `sys_contact` varchar(255) DEFAULT NULL,
  `sys_location` varchar(255) DEFAULT NULL,
  `sys_name` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `is_paused` tinyint(1) DEFAULT 0,
  `status` enum('up','down','unknown') DEFAULT 'unknown',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `interface_metrics`
--

DROP TABLE IF EXISTS `interface_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `interface_metrics` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) NOT NULL,
  `interface_index` int(11) NOT NULL,
  `interface_name` varchar(255) DEFAULT NULL,
  `alias` varchar(255) DEFAULT NULL,
  `oper_status` int(11) DEFAULT NULL,
  `speed_high` bigint(20) DEFAULT NULL,
  `mtu` int(11) DEFAULT NULL,
  `hc_in_octets` bigint(20) unsigned DEFAULT NULL,
  `hc_out_octets` bigint(20) unsigned DEFAULT NULL,
  `in_ucast_pkts` bigint(20) unsigned DEFAULT NULL,
  `in_mcast_pkts` bigint(20) unsigned DEFAULT NULL,
  `in_bcast_pkts` bigint(20) unsigned DEFAULT NULL,
  `out_ucast_pkts` bigint(20) unsigned DEFAULT NULL,
  `out_mcast_pkts` bigint(20) unsigned DEFAULT NULL,
  `out_bcast_pkts` bigint(20) unsigned DEFAULT NULL,
  `in_errors` bigint(20) unsigned DEFAULT NULL,
  `out_errors` bigint(20) unsigned DEFAULT NULL,
  `in_discards` bigint(20) unsigned DEFAULT NULL,
  `out_discards` bigint(20) unsigned DEFAULT NULL,
  `out_queue_len` int(11) DEFAULT NULL,
  `collected_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `interface_metrics_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=1833 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `protocol_metrics`
--

DROP TABLE IF EXISTS `protocol_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `protocol_metrics` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) NOT NULL,
  `tcp_curr_estab` int(11) DEFAULT NULL,
  `tcp_in_segs` bigint(20) DEFAULT NULL,
  `tcp_out_segs` bigint(20) DEFAULT NULL,
  `udp_in_datagrams` bigint(20) DEFAULT NULL,
  `udp_out_datagrams` bigint(20) DEFAULT NULL,
  `icmp_in_msgs` bigint(20) DEFAULT NULL,
  `icmp_out_msgs` bigint(20) DEFAULT NULL,
  `collected_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `protocol_metrics_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=934 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sensor_metrics`
--

DROP TABLE IF EXISTS `sensor_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sensor_metrics` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) NOT NULL,
  `sensor_name` varchar(255) DEFAULT NULL,
  `sensor_type` varchar(50) DEFAULT NULL,
  `value` float DEFAULT NULL,
  `collected_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `sensor_metrics_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `sessions`
--

DROP TABLE IF EXISTS `sessions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `sessions` (
  `token` varchar(64) NOT NULL,
  `user_id` int(11) NOT NULL,
  `expires_at` timestamp NOT NULL,
  PRIMARY KEY (`token`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `sessions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `settings`
--

DROP TABLE IF EXISTS `settings`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `settings` (
  `key_name` varchar(50) NOT NULL,
  `value_str` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`key_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `storage_metrics`
--

DROP TABLE IF EXISTS `storage_metrics`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `storage_metrics` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `device_id` int(11) NOT NULL,
  `storage_index` int(11) DEFAULT NULL,
  `storage_descr` varchar(255) DEFAULT NULL,
  `size_bytes` bigint(20) unsigned DEFAULT NULL,
  `used_bytes` bigint(20) unsigned DEFAULT NULL,
  `collected_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `storage_metrics_ibfk_1` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=10144 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `system_logs`
--

DROP TABLE IF EXISTS `system_logs`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `system_logs` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `level` varchar(10) DEFAULT NULL,
  `source` varchar(50) DEFAULT NULL,
  `message` text DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=1093 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `user_device_permissions`
--

DROP TABLE IF EXISTS `user_device_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `user_device_permissions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `device_id` int(11) NOT NULL,
  `can_write` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  UNIQUE KEY `unique_perm` (`user_id`,`device_id`),
  KEY `device_id` (`device_id`),
  CONSTRAINT `user_device_permissions_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE,
  CONSTRAINT `user_device_permissions_ibfk_2` FOREIGN KEY (`device_id`) REFERENCES `devices` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password_hash` varchar(64) NOT NULL,
  `role` enum('admin','user') NOT NULL DEFAULT 'user',
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `email` varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_uca1400_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*M!100616 SET NOTE_VERBOSITY=@OLD_NOTE_VERBOSITY */;

-- Dump completed on 2025-12-08  0:26:45
