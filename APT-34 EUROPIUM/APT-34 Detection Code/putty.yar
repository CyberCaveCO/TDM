
rule putty {
   meta:
      description = "Putty is using SSH protocol that allows authorized users to open remote shells on other computers and recently used by adversary"
      author = "CyberCave"
      reference = "https://cybercave.com.sa"
      date = "2022-09-24"
      hash1 = "8ece5f9d805fcf1d790f5e148d2a248dea4813024659eb6c6468b47004bc805f"
   strings:
      $x1 = "_ValidationTableColumnNullableMinValueMaxValueKeyTableKeyColumnCategorySetDescription_SummaryInformationPropertyIdNValueIdentifi" ascii
      $x2 = "atalErrorUserExitExitDialogExecuteActionCreateShortcutsPublishFeaturesPublishProductLEGACYINNOSETUPINSTALLERNATIVE32PROPERTYLega" ascii
      $x3 = "Primary key. Name of the icon file.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO) format.InstallExecute" ascii
      $x4 = "rstrtmgr.dll" fullword wide /* reversed goodware string 'lld.rgmtrtsr' */
      $s5 = "failed to get WixShellExecBinaryId" fullword ascii
      $s6 = "failed to get handle to kernel32.dll" fullword ascii
      $s7 = "failed to process target from CustomActionData" fullword ascii
      $s8 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s9 = "failed to get security descriptor's DACL - error code: %d" fullword ascii
      $s10 = "failed to get WixShellExecTarget" fullword ascii
      $s11 = "failed to schedule ExecServiceConfig action" fullword ascii
      $s12 = "App: %ls found running, %d processes, attempting to send message." fullword ascii
      $s13 = "Command failed to execute." fullword ascii
      $s14 = "failed to openexecute temp view with query %ls" fullword ascii
      $s15 = "WixShellExecTarget is %ls" fullword ascii
      $s16 = "The process, %ls, could not be registered with the Restart Manager (probably because the setup is not elevated and the process i" ascii
      $s17 = "failed to get message to send to users when server reboots due to service failure." fullword ascii
      $s18 = "w README fileWixShellExecTarget[#README_File]ARPPRODUCTICONManufacturerSimon TathamProductCode{E078C644-A120-4668-AD62-02E9FD530" ascii
      $s19 = "lModeecmusReinstallAllWixShellExecValidatePath[ProductName] SetupProgramFiles64FolderPuTTYTARGETDIRPFilesProgramMenuFolderj7qdqe" ascii
      $s20 = "AdminExecuteSequenceActionName of action to invoke, either in the engine or the handler DLL.ConditionOptional expression which s" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 10000KB and
      1 of ($x*) and 4 of them
}

