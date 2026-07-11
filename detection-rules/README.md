<!-- Local rules -->
<!-- Modify it at your will. -->
<!-- Copyright (C) 2015, Wazuh Inc. -->
<!-- Example -->
<group name="local,syslog">

  <rule id="100010" level="12" frequency="5" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <description>Multiple Windows logon failures - possible brute force attack (5 in 2 min).</description>
    <mitre>
      <id>T1110</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>

  <rule id="100011" level="15">
    <if_matched_sid>100010</if_matched_sid>
    <description>CRITICAL: Successful login after brute force attack - possible account compromise.</description>
    <mitre>
      <id>T1110</id>
      <id>T1078</id>
    </mitre>
    <group>authentication_success,attack,</group>
  </rule>

  <rule id="100030" level="0">
 <if_sid>92213</if_sid>
    <field name="win.eventdata.targetFilename">__PSScriptPolicyTest_</field>
    <description>False positive - PowerShell script policy self-test file (benign).</description>
    <group>false_positive,</group>
  </rule>
</group>

<group name="windows,discovery">

  <rule id="100101" level="7">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)whoami\.exe$</field>
    <description>whoami execution - System Owner/User Discovery (T1033)</description>
    <mitre>
      <id>T1033</id>
    </mitre>
    <group>sysmon_eid1_detections,windows,</group>
  </rule>

  <rule id="100102" level="9">
    <if_sid>100101</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)whoami\s+/all|whoami\s+/priv|whoami\s+/groups</field>
    <description>whoami with privilege escalation check (T1033)</description>
    <mitre>
      <id>T1033</id>
    </mitre>
 </rule>

  <rule id="100103" level="7">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)ipconfig\.exe$</field>
    <description>ipconfig execution - Network Configuration Discovery (T1016)</description>
    <mitre>
      <id>T1016</id>
    </mitre>
    <group>sysmon_eid1_detections,windows,</group>
  </rule>

  <rule id="100104" level="5">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)hostname\.exe$</field>
    <description>hostname execution - System Information Discovery (T1082)</description>
    <mitre>
      <id>T1082</id>
    </mitre>
    <group>sysmon_eid1_detections,windows,</group>
  </rule>

  <rule id="100105" level="7">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)systeminfo\.exe$</field>
    <description>systeminfo execution - System Information Discovery (T1082)</description>
<mitre>
      <id>T1082</id>
    </mitre>
  </rule>

  <rule id="100106" level="7">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)tasklist\.exe$</field>
    <description>tasklist execution - Process Discovery (T1057)</description>
    <mitre>
      <id>T1057</id>
    </mitre>
  </rule>

  <rule id="100107" level="7">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)netstat\.exe$</field>
    <description>netstat execution - Network Connection Discovery (T1049)</description>
    <mitre>
      <id>T1049</id>
    </mitre>
  </rule>
  <rule id="100031" level="8" frequency="2" timeframe="180">
  <if_matched_group>sysmon_event1</if_matched_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(whoami|systeminfo|ipconfig|nltest|hostname)\.exe</field>
  <description>Multiple discovery commands executed - possible system/account enumeration.</description>
 <mitre>
    <id>T1082</id>
    <id>T1087</id>
  </mitre>
  <group>discovery,attack,</group>
</rule>
</group>
