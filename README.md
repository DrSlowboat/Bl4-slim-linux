# Borderlands 4 Linux Slimmer

Borderlands 4 takes up a massive amount of space on your disk drive by storing old patch data and keeping voice packs that you're probably never going to use. This python script trims the fat to make it much easier to justify keeping it on your storage drive. All credit for the original idea goes to [nanafy](https://github.com/nanafy/bl-slim) but since using powershell on Linux requires you to download a whole host of files you may not need for anything else, this is a python script you can try to use instead. Nanafy's will still work if you download all the tools for powershell, and there's a fork of their repository that's meant for steamOS you can try instead.

> **Note:** Unlike Nanafy's script this doesn't cover BL3 because I don't currently have that installed and it seemed like too much work. If there's sufficient interest, I can implement it for that game as well, but feel free to adapt the current script to fit that game if you'd like and post it on GitHub. 

## Space Savings

By dropping unused foreign voice packs and deleting old patch data (without touching any actively useful game data), you can reclaim massive amounts of disk space from BL4 that you don't need to run the game. For example, if you only keep the English language pack, you can expect to see something like this:

```text
Before:    189.26 GB
After:       55.14 GB
Saved:     134.11 GB
```

> **Note:** Standard desktop file browsers (like Dolphin or Nautilus) report the *apparent* file size because the file lengths don't change. To see your actual reclaimed disk space, use terminal commands like `du -sh` on your Borderlands 4 game folder.

---

## Prerequisites

* Linux with an `ext4`, `btrfs`, or `xfs` drive (This will not work if you're dual booting and running BL4 off an NTFS drive on Linux).
* Python 3.x and pip installed. Pretty much every linux distro will come with Python and pip preinstalled, but just in case yours doesn't, install them using your distro's package manager:

* **Ubuntu / Debian:**
  ```bash
  sudo apt update && sudo apt install python3 python3-pip
  ```
  
* **Fedora:**
  ```bash
  sudo dnf install python3 python3-pip
  ```
  
* **Arch:**
  ```bash
  sudo pacman -S python python-pip
  ```

Of course, if you're using a distro that doesn't come with these preinstalled you're probably building Linux from scratch and know way more about it than I do, but never hurts to make sure.

---

## How to Use

1. Ensure Borderlands 4 is completely closed and Steam isn't actively updating or verifying files.
2. Place `bl_slim.py` in a place where you can keep track of it easily (you'll probably need to run the script again after every update).
3. Make the script executable by navigating to the folder it's in with cd or navigating to the folder with your file browser and opening a terminal window there, then type:
   ```bash
   chmod +x bl_slim.py
   ```
4. Run a dry-run scan first to preview what can be removed (you can skip this step if you've already used it and it's worked):
   ```bash
   ./bl_slim.py -Scan
   ```
5. Run the script to apply the changes:
   ```bash
   ./bl_slim.py
   ```
   * If the script cannot automatically locate your Steam library, it will prompt you to paste your Borderlands 4 game folder path. You can find this by going to **Properties** -> **Installed Files** -> **Browse** and copy/pasting the path from your file browser.
   * Follow the prompt to select which voice languages to keep (English is always kept automatically, the game breaks without it).

### Command-Line Options

| Command | What it does |
|---|---|
| `./bl_slim.py -Scan` | Dry run showing space savings without modifying any files. |
| `./bl_slim.py -Keep "English(US)"` | Keeps specified language(s) without interactive prompts. |
| `./bl_slim.py -GameDir "/path/to/Borderlands 4"` | Targets a specific game installation directory directly. |
| `./bl_slim.py -Yes` | Skips the "Go ahead? (y/n)" confirmation prompt. |

---

## Proton & Steam Launch Options (Linux / Wayland)

Running BL4 on Linux can be a bit of a pain because it doesn't play well with Wayland, and even less well with Mutter. Before you run this script, make sure your game can actually run.

If the game hangs on a black screen or fails to open a window while Steam says "Running", add these launch options to Borderlands 4 in Steam (Right-click game -> **Properties** -> **General** -> **Launch Options**): 

```bash
SteamDeck=0 PROTON_ENABLE_WAYLAND=1 PROTON_USE_WAYLAND=1 %command% 
```

Add any others you'd like to use alongside those. I specifically use proton-Experimental because I've had little luck with other compatibility tools. You can change your compatibility tool to Proton Experimental from the compatibility tab directly below general. 

---

## Undoing Changes

If you ever want to restore your game to its full factory size, open Steam, right-click **Borderlands 4** -> **Properties** -> **Installed Files** -> and click **Verify integrity of game files**. Steam will redownload any cleared data. 

## Post-Patch

After any patch of the game, you will probably need to redo this process since steam will redownload all the missing files. This effectively makes the program a lot less useful since you need to have that amount of spare space on your drive just to update it, but c'est la vie. 

## Testing

This script has been tested on CachyOS. The full list of launch commands I use is:

```bash
SteamDeck=0 WINEDLLOVERRIDES="dsound=n,b" PROTON_ENABLE_WAYLAND=1 PROTON_USE_WAYLAND=1 WAYLANDDRV_PRIMARY_MONITOR=DP-1 ENABLE_LAYER_MESA_ANTI_LAG=1 PROTON_FSR_UPGRADE=1 %command% -NoStartupMovies -pf_tricks=vcrun2022
```

WINEDLLOVERRIDES="dsound=n,b" and pf_tricks=vcrun2022 are because I'm running SDK mods (it's ridiculous that the game still hasn't separated the grapple and melee key). Mesa Anti Lag and FSR upgrade are because I'm on an AMD GPU. WAYLANDDRV is because the game was booting on my secondary monitor instead of my primary and I was getting a perpetual loading cursor over my game screen. 

If it's successfully worked for you on any other Arch, Debian or Fedora distros, let me know so I can update this. Obviously, this script is use at your own risk and is covered by the MIT license which states the same. 


