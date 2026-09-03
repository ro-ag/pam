; pam ships one console binary; the shortcuts must pass `gui`.
!macro NSIS_HOOK_POSTINSTALL
  CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "gui" "$INSTDIR\${MAINBINARYNAME}.exe" 0
  IfFileExists "$DESKTOP\${PRODUCTNAME}.lnk" 0 +2
    CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe" "gui" "$INSTDIR\${MAINBINARYNAME}.exe" 0
!macroend
