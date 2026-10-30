import { chmodSync, lstatSync, mkdirSync, readdirSync, realpathSync, writeFileSync, renameSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { resolve, parse, join, dirname } from 'node:path';
import { requireThat } from '../core/model.js';

// The path is passed in an environment variable, never interpolated into code.
const protectWindows = String.raw`
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
$item=Get-Item -LiteralPath $env:PLK_PRIVATE_PATH -Force
if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'REPARSE_POINT_NOT_ALLOWED'}
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=if($item.PSIsContainer){[Security.AccessControl.DirectorySecurity]::new()}else{[Security.AccessControl.FileSecurity]::new()}
$acl.SetAccessRuleProtection($true,$false)
foreach($allowed in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){
  $inherit=if($item.PSIsContainer){[Security.AccessControl.InheritanceFlags]'ContainerInherit,ObjectInherit'}else{[Security.AccessControl.InheritanceFlags]::None}
  $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($allowed,[Security.AccessControl.FileSystemRights]::FullControl,$inherit,[Security.AccessControl.PropagationFlags]::None,[Security.AccessControl.AccessControlType]::Allow))
}
if($item.PSIsContainer){[IO.Directory]::SetAccessControl($item.FullName,$acl)}else{[IO.File]::SetAccessControl($item.FullName,$acl)}
`;

/** For a service-owned path only. Never call this on a shared drive or system directory. */
export function protectPrivatePath(path: string, recursive = false): void {
  const absolute = resolve(path);
  requireThat(absolute !== parse(absolute).root, 'PRIVATE_PATH_MUST_NOT_BE_DRIVE_ROOT');
  const stat = lstatSync(absolute);
  const real = realpathSync(absolute);
  requireThat(!stat.isSymbolicLink() && (process.platform === 'win32' ? real.toLowerCase() === absolute.toLowerCase() : real === absolute), 'PRIVATE_PATH_LINK_NOT_ALLOWED');
  if (process.platform === 'win32') {
    execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', protectWindows], {
      env: { ...process.env, PLK_PRIVATE_PATH: absolute }, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'],
    });
  } else chmodSync(absolute, stat.isDirectory() ? 0o700 : 0o600);
  if (recursive && stat.isDirectory()) {
    for (const name of readdirSync(absolute)) protectPrivatePath(join(absolute, name), true);
  }
}

export function privateDirectory(path: string): string {
  const absolute = resolve(path);
  mkdirSync(absolute, { recursive: true, mode: 0o700 });
  protectPrivatePath(absolute);
  return absolute;
}

/** Replace a service-owned file after completely writing and protecting its replacement. */
export function writePrivateAtomic(path: string, content: string | Uint8Array): void {
  const target = resolve(path);
  privateDirectory(dirname(target));
  if (existsSync(target)) requireThat(!lstatSync(target).isSymbolicLink(), 'PRIVATE_PATH_LINK_NOT_ALLOWED');
  const temporary = `${target}.${randomUUID()}.tmp`;
  writeFileSync(temporary, content, { flag: 'wx', mode: 0o600 });
  protectPrivatePath(temporary);
  renameSync(temporary, target);
}
