
#pragma once

#ifndef BLOODHUNT_H

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <iostream>
#include <dwmapi.h>
#include  <d3d9.h>
#include  <d3dx9.h>

#include "singleton.h"
#include "vector.h"
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "dwmapi.lib")

//ACharacter : APawn

inline namespace BloodHunt
{
	class Variables : public Singleton<Variables>
	{
	public:
		const char* dwProcessName = "DeadByDaylight-Win64-Shipping.exe";
		DWORD dwProcessId = NULL;
		uint64_t dwProcess_Base = NULL;
		HWND gameHWND = NULL;

		int CameraManager = NULL;
		int actor_count = NULL;
		int ScreenHeight = GetSystemMetrics(SM_CYSCREEN);
		int ScreenWidth = GetSystemMetrics(SM_CXSCREEN);
		int ScreenLeft = NULL;
		int ScreenRight = NULL;
		int ScreenTop = NULL;
		int ScreenBottom = NULL;

		float ScreenCenterX = ScreenWidth / 2;
		float ScreenCenterY = ScreenHeight / 2;

		DWORD_PTR game_instance = NULL;
		DWORD_PTR u_world = NULL;
		DWORD_PTR local_player_pawn = NULL;
		DWORD_PTR local_player_array = NULL;
		DWORD_PTR local_player = NULL;
		DWORD_PTR local_player_root = NULL;
		DWORD_PTR local_player_controller = NULL;
		DWORD_PTR local_player_state = NULL;
		DWORD_PTR persistent_level = NULL;
		DWORD_PTR actors = NULL;
		DWORD_PTR ranged_weapon_component = NULL;
		DWORD_PTR equipped_weapon_type = NULL;


	};
#define GameVars BloodHunt::Variables::Get()

	class Offsets : public Singleton<Offsets>
	{
	public:

		DWORD offset_u_world = 0xD036850; //48 8B 1D ? ? ? ? 48 85 DB 74 3B
		DWORD offset_g_names = 0xCE58680; //48 8D 1D ? ? ? ? EB 16 48 8D 0D ? ? ? ? E8 ? ? ? ? 48 8B D8 C6 05 ? ? ? ? ? 0F 28
		DWORD offset_g_objects = 0xCEB0CB0;
		DWORD offset_camera_manager = 0x2d0; // APlayerController->PlayerCameraManager
		DWORD offset_camera_cache = 0x1af0; //APlayerCameraManager->CameraCachePrivate
		DWORD offset_persistent_level = 0x38; //UWorld->PersistentLevel
		DWORD offset_game_instance = 0x190; //UWolrd->OwningGameInstance
		DWORD offset_local_players_array = 0x40; //UGameInstance->LocalPlayers
		DWORD offset_player_controller = 0x38; //UPlayer->PlayerController
		DWORD offset_apawn = 0x2b8;  //APlayerController->AcknowledgedPawn
		DWORD offset_root_component = 0x140; //AActor->RootComponent
		DWORD offset_actor_array = 0xa0; //UNetConnection->OwningActor
		DWORD offset_actor_count = 0xa8; //UNetConnection->MaxPacket
		DWORD offset_actor_id = 0x18;
		DWORD offset_player_name = 0x318; //PlayerNamePrivate
		
		DWORD offset_levels = 0x148; //TArray<struct ULevel*> Levels;
		DWORD offset_teamid = 0x3d8; // Offsets::Classes::1PlayerState::Ainfo::AActor::UObject::ASQPlayerState::TeamId

		DWORD offset_player_state = 0x250; //0x238 0x250 //APawn->PlayerState
		DWORD offset_actor_mesh = 0x298; // Classes::ACharacter::Mesh / ++++++

		DWORD offset_bone_array = 0x510;  // Classes::USkeletalMeshComponent::CachedBoneSpaceTransforms / or CachedComponentSpaceTransforms  StaticMeshComponent/StaticMesh +++
		DWORD offset_component_to_world = 0x1E0; // Classes::USceneComponent::bComponentToWorldUpdated / ULevel	WorldSettings

		DWORD offset_relative_location = 0x134; //USceneComponent->RelativeLocation

		DWORD offset_last_submit_time = 0x2bc; // AServerStatReplicator -> NumRelevantDeletedActors
		DWORD offset_last_render_time = 0x2c4; // AServerStatReplicator -> NumReplicatedActors
		DWORD offset_health = 0x1f8;
		//DWORD offset_max_health = 0x364;
	};

#define GameOffset BloodHunt::Offsets::Get()
}
#endif  !BLOODHUNT_H

