// Build script: embeds the UAC manifest, the application icon, and a VERSIONINFO
// resource (File version / Product version shown in Explorer → Properties →
// Details). The icon + version resource script is GENERATED here from Cargo's
// version so it always stays in sync — bump `version` in Cargo.toml and the
// stamped file version follows automatically.
use embed_manifest::manifest::ExecutionLevel;
use embed_manifest::{embed_manifest, new_manifest};

fn main() {
    if std::env::var_os("CARGO_CFG_WINDOWS").is_some() {
        // 1. requireAdministrator manifest → UAC prompt on launch.
        embed_manifest(
            new_manifest("DefenderControl")
                .requested_execution_level(ExecutionLevel::RequireAdministrator),
        )
        .expect("unable to embed manifest file");

        // 2. Generate <OUT_DIR>/app.rc with the icon + version info.
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_owned());

        let mut parts = version.split('.').map(|s| s.parse::<u16>().unwrap_or(0));
        let major = parts.next().unwrap_or(0);
        let minor = parts.next().unwrap_or(0);
        let patch = parts.next().unwrap_or(0);
        let display = if patch == 0 {
            format!("v{major}.{minor}")
        } else {
            format!("v{major}.{minor}.{patch}")
        };

        // Absolute path to the .ico, backslashes doubled for the .rc string.
        let ico = format!(
            r"{manifest_dir}\icons and logo\defendercontrol420-shield-transparent-v2.ico"
        )
        .replace('\\', r"\\");

        let rc = format!(
            r#"1 ICON "{ico}"
1 VERSIONINFO
FILEVERSION {major},{minor},{patch},0
PRODUCTVERSION {major},{minor},{patch},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS 0x40004L
FILETYPE 0x1L
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "MrExploit"
      VALUE "FileDescription", "Defender Control"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "defender-control"
      VALUE "OriginalFilename", "defender-control.exe"
      VALUE "ProductName", "Defender Control"
      VALUE "ProductVersion", "{display}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#
        );

        let rc_path = std::path::Path::new(&out_dir).join("app.rc");
        std::fs::write(&rc_path, rc).expect("write generated app.rc");

        embed_resource::compile(&rc_path, embed_resource::NONE)
            .manifest_optional()
            .expect("failed to compile resources");
    }
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=CARGO_PKG_VERSION");
    println!("cargo:rerun-if-changed=icons and logo/defendercontrol420-shield-transparent-v2.ico");
}
