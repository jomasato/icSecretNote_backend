import Array "mo:base/Array";
import Blob "mo:base/Blob";
import HashMap "mo:base/HashMap";
import Iter "mo:base/Iter";
import Principal "mo:base/Principal";
import Text "mo:base/Text";
import Time "mo:base/Time";
import Result "mo:base/Result";
import Buffer "mo:base/Buffer";
import Option "mo:base/Option";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Cycles "mo:base/ExperimentalCycles";

actor SecureNotes {
  // 型定義
  public type NoteId = Text;
  public type ShareId = Text;
  public type DeviceId = Text;
  
  // キャニスターに保存される暗号化されたメモ
  public type EncryptedNote = {
    id : NoteId;
    title : Blob; // 暗号化されたタイトル
    content : Blob; // 暗号化された内容
    created : Time.Time;
    updated : Time.Time
  };
  
  // ガーディアンのキーシェア
  public type KeyShare = {
    shareId : ShareId;
    encryptedShare : Blob; // ガーディアンの公開鍵で暗号化されたシェア
    guardianPrincipal : Principal;
    userPrincipal : Principal
  };
  
  // ユーザープロファイル拡張版
  public type UserProfile = {
    principal : Principal;
    totalGuardians : Nat;
    requiredShares : Nat; // シャミアのスキームでのk
    recoveryEnabled : Bool;
    publicRecoveryData : ?Blob; // リカバリーに必要な公開データ（暗号化されていない）
    devices : [DeviceInfo]; // 認証済みデバイスのリスト
  };
  
  // デバイス情報
  public type DeviceInfo = {
    id : DeviceId;
    name : Text;
    publicKey : Blob; // デバイスの公開鍵
    registrationTime : Time.Time;
    lastAccessTime : Time.Time;
  };
  
  // リカバリー後のアクセス情報
  public type RecoveryAccess = {
    tempPrincipal : Principal; // 一時的なリカバリー用プリンシパル
    originalPrincipal : Principal; // 元のユーザープリンシパル
    accessKey : Blob; // 暗号化されたアクセス情報
    expiryTime : Time.Time; // アクセス期限
    isUsed : Bool; // 使用済みかどうか
  };
  
  // リカバリーセッション（拡張）
  public type RecoverySession = {
    userPrincipal : Principal;
    requestTime : Time.Time;
    approvedGuardians : [Principal];
    tempAccessPrincipal : ?Principal;
    status : RecoveryStatus;
    collectedShares : [ShareId]; // 収集されたシェアのID
  };
  
  public type RecoveryStatus = {
    #Requested; // リクエスト中
    #InProgress; // 進行中
    #ApprovalComplete; // 承認完了
    #SharesCollected; // シェア収集完了
    #Completed; // 完了
    #Failed; // 失敗
  };
  
  // ガーディアン管理アクション
  public type GuardianAction = {
    #Add; // ガーディアン追加
    #Remove; // ガーディアン削除
    #Replace : Principal; // ガーディアン交換（古いガーディアンのプリンシパル）
  };
  
  // アップグレード用の安定ストレージ
  private stable var notesEntries : [(Principal, [(NoteId, EncryptedNote)])] = [];
  private stable var sharesEntries : [(ShareId, KeyShare)] = [];
  private stable var userProfilesEntries : [(Principal, UserProfile)] = [];
  private stable var recoverySessionsEntries : [(Principal, RecoverySession)] = [];
  private stable var recoveryAccessEntries : [(Principal, RecoveryAccess)] = [];
  
  // ハッシュマップストレージ
  private var notes = HashMap.HashMap<Principal, HashMap.HashMap<NoteId, EncryptedNote>>(
    0,
    Principal.equal,
    Principal.hash
  );
  private var shares = HashMap.HashMap<ShareId, KeyShare>(
    0,
    Text.equal,
    Text.hash
  );
  private var userProfiles = HashMap.HashMap<Principal, UserProfile>(
    0,
    Principal.equal,
    Principal.hash
  );
  private var recoverySessions = HashMap.HashMap<Principal, RecoverySession>(
    0,
    Principal.equal,
    Principal.hash
  );
  private var recoveryAccesses = HashMap.HashMap<Principal, RecoveryAccess>(
    0,
    Principal.equal,
    Principal.hash
  );
  
  // アップグレードフック（全データ構造を一度に処理）
  system func preupgrade() {
    // メモデータの変換
    let notesBuffer = Buffer.Buffer<(Principal, [(NoteId, EncryptedNote)])>(notes.size());
    for ((userPrincipal, userNotes) in notes.entries()) {
      let notesArray = Iter.toArray(userNotes.entries());
      notesBuffer.add((userPrincipal, notesArray))
    };
    notesEntries := Buffer.toArray(notesBuffer);
    
    // シェアの変換
    sharesEntries := Iter.toArray(shares.entries());
    
    // ユーザープロファイルの変換
    userProfilesEntries := Iter.toArray(userProfiles.entries());
    
    // リカバリーセッションの変換
    recoverySessionsEntries := Iter.toArray(recoverySessions.entries());
    
    // リカバリーアクセスの変換
    recoveryAccessEntries := Iter.toArray(recoveryAccesses.entries());
  };
  
  system func postupgrade() {
    // メモの復元
    for ((principal, noteEntries) in notesEntries.vals()) {
      let userNotes = HashMap.fromIter<NoteId, EncryptedNote>(
        noteEntries.vals(),
        10,
        Text.equal,
        Text.hash
      );
      notes.put(principal, userNotes)
    };
    notesEntries := [];
    
    // シェアの復元
    for ((id, share) in sharesEntries.vals()) {
      shares.put(id, share)
    };
    sharesEntries := [];
    
    // ユーザープロファイルの復元
    for ((principal, profile) in userProfilesEntries.vals()) {
      userProfiles.put(principal, profile)
    };
    userProfilesEntries := [];
    
    // リカバリーセッションの復元
    for ((principal, session) in recoverySessionsEntries.vals()) {
      recoverySessions.put(principal, session)
    };
    recoverySessionsEntries := [];
    
    // リカバリーアクセスの復元
    for ((principal, access) in recoveryAccessEntries.vals()) {
      recoveryAccesses.put(principal, access)
    };
    recoveryAccessEntries := [];
  };
  
  // 互換性のための元のインターフェースを保持
  public shared (msg) func createProfile(totalGuardians : Nat, requiredShares : Nat) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // 入力の検証
    if (requiredShares > totalGuardians) {
      return #err("必要なシェア数は総ガーディアン数を超えることはできません");
    };
    
    if (requiredShares < 2) {
      return #err("セキュリティのため少なくとも2つのシェアが必要です");
    };
    
    // デフォルト値で新しい関数を呼び出す
    let defaultDeviceName = "Default Device";
    let defaultPublicKey = Blob.fromArray([0,0,0,0]); // ダミーの公開鍵
    
    let result = await createProfileWithDevice(totalGuardians, requiredShares, defaultDeviceName, defaultPublicKey);
    
    // DeviceIdを無視して()を返す
    switch (result) {
      case (#ok(_)) { return #ok() };
      case (#err(e)) { return #err(e) };
    }
  };
  
  // 新しいインターフェース（デバイス情報付き）
  public shared (msg) func createProfileWithDevice(
    totalGuardians : Nat, 
    requiredShares : Nat,
    deviceName : Text,
    devicePublicKey : Blob
  ) : async Result.Result<DeviceId, Text> {
    let caller = msg.caller;
    
    // 入力の検証
    if (requiredShares > totalGuardians) {
      return #err("必要なシェア数は総ガーディアン数を超えることはできません");
    };
    
    if (requiredShares < 2) {
      return #err("セキュリティのため少なくとも2つのシェアが必要です");
    };
    
    // デバイス情報の作成
    let deviceId = generateId("device");
    let device : DeviceInfo = {
      id = deviceId;
      name = deviceName;
      publicKey = devicePublicKey;
      registrationTime = Time.now();
      lastAccessTime = Time.now();
    };
    
    let profile : UserProfile = {
      principal = caller;
      totalGuardians = totalGuardians;
      requiredShares = requiredShares;
      recoveryEnabled = false; // シェアが配布されると有効になる
      publicRecoveryData = null;
      devices = [device];
    };
    
    userProfiles.put(caller, profile);
    return #ok(deviceId);
  };
  
  public shared (msg) func getProfile() : async Result.Result<UserProfile, Text> {
    let caller = msg.caller;
    
    switch (userProfiles.get(caller)) {
      case null { return #err("プロファイルが見つかりません") };
      case (?profile) { return #ok(profile) };
    };
  };
  
  // 公開リカバリーデータの設定（フロントエンドで生成された情報）
  public shared (msg) func setPublicRecoveryData(data : Blob) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    switch (userProfiles.get(caller)) {
      case null { return #err("プロファイルが見つかりません") };
      case (?profile) {
        let updatedProfile = {
          principal = profile.principal;
          totalGuardians = profile.totalGuardians;
          requiredShares = profile.requiredShares;
          recoveryEnabled = profile.recoveryEnabled;
          publicRecoveryData = ?data;
          devices = profile.devices;
        };
        
        userProfiles.put(caller, updatedProfile);
        return #ok();
      };
    };
  };
  
  // メモ管理
  public shared (msg) func saveNote(id : NoteId, title : Blob, content : Blob) : async Result.Result<NoteId, Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    // ユーザーのメモコレクションを取得または作成
    var userNotes = switch (notes.get(actualPrincipal)) {
      case null {
        let newMap = HashMap.HashMap<NoteId, EncryptedNote>(10, Text.equal, Text.hash);
        notes.put(actualPrincipal, newMap);
        newMap;
      };
      case (?existing) { existing };
    };
    
    let note : EncryptedNote = {
      id = id;
      title = title;
      content = content;
      created = Time.now();
      updated = Time.now();
    };
    
    userNotes.put(id, note);
    return #ok(id);
  };
  
  public shared (msg) func updateNote(id : NoteId, title : Blob, content : Blob) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (notes.get(actualPrincipal)) {
      case null { return #err("メモが見つかりません") };
      case (?userNotes) {
        switch (userNotes.get(id)) {
          case null { return #err("指定されたIDのメモが見つかりません") };
          case (?existingNote) {
            let updatedNote : EncryptedNote = {
              id = existingNote.id;
              title = title;
              content = content;
              created = existingNote.created;
              updated = Time.now();
            };
            
            userNotes.put(id, updatedNote);
            return #ok();
          };
        };
      };
    };
  };
  
  public shared (msg) func getNotes() : async [EncryptedNote] {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (notes.get(actualPrincipal)) {
      case null { return [] };
      case (?userNotes) {
        let notesArray = Buffer.Buffer<EncryptedNote>(userNotes.size());
        for ((_, note) in userNotes.entries()) {
          notesArray.add(note);
        };
        
        return Buffer.toArray(notesArray);
      };
    };
  };
  
  public shared (msg) func getNote(id : NoteId) : async Result.Result<EncryptedNote, Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (notes.get(actualPrincipal)) {
      case null { return #err("メモが見つかりません") };
      case (?userNotes) {
        switch (userNotes.get(id)) {
          case null { return #err("メモが見つかりません") };
          case (?note) { return #ok(note) };
        };
      };
    };
  };
  
  public shared (msg) func deleteNote(id : NoteId) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (notes.get(actualPrincipal)) {
      case null { return #err("メモが見つかりません") };
      case (?userNotes) {
        switch (userNotes.get(id)) {
          case null { return #err("メモが見つかりません") };
          case (_) {
            userNotes.delete(id);
            return #ok();
          };
        };
      };
    };
  };
  
  // デバイス管理
  public shared (msg) func addDevice(
    deviceName : Text, 
    devicePublicKey : Blob, 
    encryptedDeviceData : Blob
  ) : async Result.Result<DeviceId, Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (userProfiles.get(actualPrincipal)) {
      case null { return #err("プロファイルが見つかりません") };
      case (?profile) {
        let deviceId = generateId("device");
        let device : DeviceInfo = {
          id = deviceId;
          name = deviceName;
          publicKey = devicePublicKey;
          registrationTime = Time.now();
          lastAccessTime = Time.now();
        };
        
        // 新しいデバイスリストを作成
        let deviceBuffer = Buffer.Buffer<DeviceInfo>(profile.devices.size() + 1);
        for (existingDevice in profile.devices.vals()) {
          deviceBuffer.add(existingDevice);
        };
        deviceBuffer.add(device);
        
        let updatedProfile = {
          principal = profile.principal;
          totalGuardians = profile.totalGuardians;
          requiredShares = profile.requiredShares;
          recoveryEnabled = profile.recoveryEnabled;
          publicRecoveryData = profile.publicRecoveryData;
          devices = Buffer.toArray(deviceBuffer);
        };
        
        userProfiles.put(actualPrincipal, updatedProfile);
        return #ok(deviceId);
      };
    };
  };
  
  public shared (msg) func removeDevice(deviceId : DeviceId) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (userProfiles.get(actualPrincipal)) {
      case null { return #err("プロファイルが見つかりません") };
      case (?profile) {
        // 少なくとも1つのデバイスは残す必要がある
        if (profile.devices.size() <= 1) {
          return #err("少なくとも1つのデバイスが必要です");
        };
        
        // デバイスが存在するか確認
        var deviceExists = false;
        for (device in profile.devices.vals()) {
          if (device.id == deviceId) {
            deviceExists := true;
          };
        };
        
        if (not deviceExists) {
          return #err("デバイスが見つかりません");
        };
        
        // 削除対象以外のデバイスをフィルタリング
        let filteredDevices = Array.filter<DeviceInfo>(
          profile.devices, 
          func(d : DeviceInfo) : Bool { d.id != deviceId }
        );
        
        let updatedProfile = {
          principal = profile.principal;
          totalGuardians = profile.totalGuardians;
          requiredShares = profile.requiredShares;
          recoveryEnabled = profile.recoveryEnabled;
          publicRecoveryData = profile.publicRecoveryData;
          devices = filteredDevices;
        };
        
        userProfiles.put(actualPrincipal, updatedProfile);
        return #ok();
      };
    };
  };
  
  public shared (msg) func getDevices() : async Result.Result<[DeviceInfo], Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (userProfiles.get(actualPrincipal)) {
      case null { return #err("プロファイルが見つかりません") };
      case (?profile) {
        return #ok(profile.devices);
      };
    };
  };
  
  // ガーディアン管理
  public shared (msg) func manageGuardian(
    guardianPrincipal : Principal,
    action : GuardianAction,
    encryptedShare : ?Blob,
    shareId : ?Text
  ) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    switch (userProfiles.get(actualPrincipal)) {
      case null { return #err("プロファイルが見つかりません") };
      case (?profile) {
        // ガーディアンが自分自身かチェック
        if (guardianPrincipal == actualPrincipal) {
          return #err("自分自身をガーディアンにはできません");
        };
        
        switch (action) {
          case (#Add) {
            // ガーディアン追加の場合、シェアが必要
            switch (encryptedShare, shareId) {
              case (?share, ?id) {
                let newShareId = id;
                // キーシェアの保存
                let keyShare : KeyShare = {
                  shareId = newShareId;
                  encryptedShare = share;
                  guardianPrincipal = guardianPrincipal;
                  userPrincipal = actualPrincipal;
                };
                
                shares.put(newShareId, keyShare);
                
                // ガーディアン数が閾値を満たしたらリカバリーを有効化
                let sharesForUser = getSharesForUser(actualPrincipal);
                
                if (sharesForUser.size() >= profile.totalGuardians) {
                  let updatedProfile = {
                    principal = profile.principal;
                    totalGuardians = profile.totalGuardians;
                    requiredShares = profile.requiredShares;
                    recoveryEnabled = true;
                    publicRecoveryData = profile.publicRecoveryData;
                    devices = profile.devices;
                  };
                  
                  userProfiles.put(actualPrincipal, updatedProfile);
                };
                
                return #ok();
              };
              case _ { return #err("シェア情報が不足しています") };
            };
          };
          
          case (#Remove) {
            // ガーディアン削除の場合、該当するシェアを削除
            let userShares = getSharesForUser(actualPrincipal);
            for (share in userShares.vals()) {
              if (share.guardianPrincipal == guardianPrincipal) {
                shares.delete(share.shareId);
              };
            };
            
            // リカバリーが有効かを再評価
            let remainingShares = getSharesForUser(actualPrincipal);
            let recoveryEnabled = remainingShares.size() >= profile.requiredShares;
            
            let updatedProfile = {
              principal = profile.principal;
              totalGuardians = profile.totalGuardians;
              requiredShares = profile.requiredShares;
              recoveryEnabled = recoveryEnabled;
              publicRecoveryData = profile.publicRecoveryData;
              devices = profile.devices;
            };
            
            userProfiles.put(actualPrincipal, updatedProfile);
            return #ok();
          };
          
          case (#Replace(oldGuardian)) {
            // 古いガーディアンのシェアを見つけて削除
            var oldShareId : ?Text = null;
            let userShares = getSharesForUser(actualPrincipal);
            
            for (share in userShares.vals()) {
              if (share.guardianPrincipal == oldGuardian) {
                oldShareId := ?share.shareId;
                shares.delete(share.shareId);
              };
            };
            
            // 新しいガーディアンのシェアを追加
            switch (encryptedShare, shareId) {
              case (?share, ?id) {
                let newShareId = id;
                let keyShare : KeyShare = {
                  shareId = newShareId;
                  encryptedShare = share;
                  guardianPrincipal = guardianPrincipal;
                  userPrincipal = actualPrincipal;
                };
                
                shares.put(newShareId, keyShare);
                return #ok();
              };
              case _ { return #err("シェア情報が不足しています") };
            };
          };
        };
      };
    };
  };
  
  public shared (msg) func getMyGuardians() : async [(Principal, Bool)] {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    let userShares = getSharesForUser(actualPrincipal);
    let result = Buffer.Buffer<(Principal, Bool)>(0);
    
    for (share in userShares.vals()) {
      // リカバリーリクエストを確認
      let hasApproved = switch (recoverySessions.get(actualPrincipal)) {
        case null { false };
        case (?session) {
          Array.find<Principal>(
            session.approvedGuardians,
            func(p : Principal) : Bool { p == share.guardianPrincipal }
          ) != null;
        };
      };
      
      result.add((share.guardianPrincipal, hasApproved));
    };
    
    return Buffer.toArray(result);
  };
  
  // リカバリー管理
  public shared (msg) func storeKeyShare(
    shareId : ShareId, 
    encryptedShare : Blob, 
    guardianPrincipal : Principal
  ) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // ユーザープロファイルの検証
    switch (userProfiles.get(caller)) {
      case null { return #err("ユーザープロファイルが見つかりません") };
      case (?profile) {
        // キーシェアの保存
        let keyShare : KeyShare = {
          shareId = shareId;
          encryptedShare = encryptedShare;
          guardianPrincipal = guardianPrincipal;
          userPrincipal = caller;
        };
        
        shares.put(shareId, keyShare);
        
        // すべてのシェアが保存されていればリカバリーを有効化
        let sharesForUser = getSharesForUser(caller);
        
        if (sharesForUser.size() >= profile.totalGuardians) {
          let updatedProfile = {
            principal = profile.principal;
            totalGuardians = profile.totalGuardians;
            requiredShares = profile.requiredShares;
            recoveryEnabled = true;
            publicRecoveryData = profile.publicRecoveryData;
            devices = profile.devices;
          };
          
          userProfiles.put(caller, updatedProfile);
        };
        
        return #ok();
      };
    };
  };
  
  public shared (msg) func getMyKeyShare(userPrincipal : Principal) : async Result.Result<KeyShare, Text> {
    let caller = msg.caller;
    
    // このガーディアンとユーザーのシェアを検索
    for ((_, share) in shares.entries()) {
      if (share.guardianPrincipal == caller and share.userPrincipal == userPrincipal) {
        return #ok(share);
      };
    };
    
    return #err("キーシェアが見つかりません");
  };
  
  // リカバリーセッション管理
  public shared (msg) func initiateRecovery(userToRecover : Principal) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // ユーザーが存在し、リカバリーが有効かチェック
    switch (userProfiles.get(userToRecover)) {
      case null { return #err("ユーザーが見つかりません") };
      case (?profile) {
        if (not profile.recoveryEnabled) {
          return #err("リカバリーが有効になっていません");
        };
        
        // 既存のセッションをリセット
        let newSession : RecoverySession = {
          userPrincipal = userToRecover;
          requestTime = Time.now();
          approvedGuardians = [];
          tempAccessPrincipal = null;
          status = #Requested;
          collectedShares = [];
        };
        
        recoverySessions.put(userToRecover, newSession);
        return #ok();
      };
    };
  };
  
  public shared (msg) func approveRecovery(userToRecover : Principal) : async Result.Result<(), Text> {
    // ガーディアンがリカバリーを承認
    let guardian = msg.caller;
    
    // セッションを取得
    switch (recoverySessions.get(userToRecover)) {
      case null { return #err("リカバリーセッションが見つかりません") };
      case (?session) {
        // このガーディアンがユーザーのガーディアンかチェック
        var isGuardian = false;
        let userShares = getSharesForUser(userToRecover);
        
        for (share in userShares.vals()) {
          if (share.guardianPrincipal == guardian) {
            isGuardian := true;
          };
        };
        
        if (not isGuardian) {
          return #err("あなたはこのユーザーのガーディアンではありません");
        };
        
        // 既に承認しているか確認
        for (approvedGuardian in session.approvedGuardians.vals()) {
          if (approvedGuardian == guardian) {
            return #err("すでにリカバリーを承認しています");
          };
        };
        
        // 承認を追加
        let approvedBuffer = Buffer.Buffer<Principal>(session.approvedGuardians.size() + 1);
        for (g in session.approvedGuardians.vals()) {
          approvedBuffer.add(g);
        };
        approvedBuffer.add(guardian);
        
        let newApprovals = Buffer.toArray(approvedBuffer);
        
        // ユーザープロファイルを取得して必要な承認数を確認
        switch (userProfiles.get(userToRecover)) {
          case null { return #err("リカバリー対象のユーザーが見つかりません") };
          case (?profile) {
            var newStatus = session.status;
            
            if (newApprovals.size() >= profile.requiredShares) {
              // リカバリーに十分な承認を得た
              newStatus := #ApprovalComplete;
            };
            
            let updatedSession : RecoverySession = {
              userPrincipal = session.userPrincipal;
              requestTime = session.requestTime;
              approvedGuardians = newApprovals;
              tempAccessPrincipal = session.tempAccessPrincipal;
              status = newStatus;
              collectedShares = session.collectedShares;
            };
            
            recoverySessions.put(userToRecover, updatedSession);
            return #ok();
          };
        };
      };
    };
  };
  
  public shared (msg) func submitRecoveryShare(
    userToRecover : Principal, 
    shareId : ShareId
  ) : async Result.Result<(), Text> {
    let guardian = msg.caller;
    
    // セッションを取得
    switch (recoverySessions.get(userToRecover)) {
      case null { return #err("リカバリーセッションが見つかりません") };
      case (?session) {
        // セッションステータスを確認
        switch (session.status) {
          case (#Requested) { return #err("リカバリーセッションはシェア収集段階ではありません") };
          case (#Completed) { return #err("リカバリーセッションはシェア収集段階ではありません") };
          case (#Failed) { return #err("リカバリーセッションはシェア収集段階ではありません") };
          case (#ApprovalComplete) { /* OK - 続行 */ };
          case (#InProgress) { /* OK - 続行 */ };
          case (#SharesCollected) { /* OK - 続行 */ };
        };
        
        // ガーディアンが承認しているか確認
        let hasApproved = Array.find<Principal>(
          session.approvedGuardians,
          func(p : Principal) : Bool { p == guardian }
        ) != null;
        
        if (not hasApproved) {
          return #err("リカバリーをまず承認する必要があります");
        };
        
        // シェアが有効か確認
        switch (shares.get(shareId)) {
          case null { return #err("シェアが見つかりません") };
          case (?share) {
            if (share.guardianPrincipal != guardian or share.userPrincipal != userToRecover) {
              return #err("このシェアは無効です");
            };
            
            // シェアが既に提出されていないか確認
            let alreadySubmitted = Array.find<ShareId>(
              session.collectedShares,
              func(id : ShareId) : Bool { id == shareId }
            ) != null;
            
            if (alreadySubmitted) {
              return #err("このシェアは既に提出されています");
            };
            
            // シェアを追加
            let sharesBuffer = Buffer.Buffer<ShareId>(session.collectedShares.size() + 1);
            for (id in session.collectedShares.vals()) {
              sharesBuffer.add(id);
            };
            sharesBuffer.add(shareId);
            
            let newCollectedShares = Buffer.toArray(sharesBuffer);
            
            // ユーザープロファイルを取得して必要なシェア数を確認
            switch (userProfiles.get(userToRecover)) {
              case null { return #err("リカバリー対象のユーザーが見つかりません") };
              case (?profile) {
                // 収集したシェア数に基づいて適切なステータスの新しいセッションを作成
                let updatedSession : RecoverySession = if (newCollectedShares.size() >= profile.requiredShares) {
                  // リカバリーに十分なシェアを得た
                  {
                    userPrincipal = session.userPrincipal;
                    requestTime = session.requestTime;
                    approvedGuardians = session.approvedGuardians;
                    tempAccessPrincipal = session.tempAccessPrincipal;
                    status = #SharesCollected;
                    collectedShares = newCollectedShares;
                  }
                } else {
                  {
                    userPrincipal = session.userPrincipal;
                    requestTime = session.requestTime;
                    approvedGuardians = session.approvedGuardians;
                    tempAccessPrincipal = session.tempAccessPrincipal;
                    status = #InProgress;
                    collectedShares = newCollectedShares;
                  }
                };
                
                recoverySessions.put(userToRecover, updatedSession);
                return #ok();
              };
            };
          };
        };
      };
    };
  };
  
  public shared (msg) func finalizeRecovery(
    userToRecover : Principal,
    temporaryPrincipal : Principal,
    encryptedAccessKey : Blob
  ) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // セッションを取得
    switch (recoverySessions.get(userToRecover)) {
      case null { return #err("リカバリーセッションが見つかりません") };
      case (?session) {
        // セッションステータスを確認
        if (session.status != #SharesCollected) {
          return #err("リカバリーセッションは完了準備ができていません");
        };
        
        // 一時アクセストークンの作成（30日有効）
        let expiryTime = Time.now() + (30 * 24 * 60 * 60 * 1_000_000_000);
        
        let access : RecoveryAccess = {
          tempPrincipal = temporaryPrincipal;
          originalPrincipal = userToRecover;
          accessKey = encryptedAccessKey;
          expiryTime = expiryTime;
          isUsed = false;
        };
        
        recoveryAccesses.put(temporaryPrincipal, access);
        
        // セッションを更新
        let updatedSession : RecoverySession = {
          userPrincipal = session.userPrincipal;
          requestTime = session.requestTime;
          approvedGuardians = session.approvedGuardians;
          tempAccessPrincipal = ?temporaryPrincipal;
          status = #Completed;
          collectedShares = session.collectedShares;
        };
        
        recoverySessions.put(userToRecover, updatedSession);
        return #ok();
      };
    };
  };
  
  public shared (msg) func getRecoveryStatus(userToRecover : Principal) : async Result.Result<(RecoverySession, UserProfile), Text> {
    // リカバリー状態の取得
    switch (userProfiles.get(userToRecover)) {
      case null { return #err("ユーザーが見つかりません") };
      case (?profile) {
        let session = switch (recoverySessions.get(userToRecover)) {
          case null {
            let emptySession : RecoverySession = {
              userPrincipal = userToRecover;
              requestTime = 0;
              approvedGuardians = [];
              tempAccessPrincipal = null;
              status = #Requested;
              collectedShares = [];
            };
            emptySession;
          };
          case (?existing) { existing };
        };
        
        return #ok((session, profile));
      };
    };
  };
  
  public shared (msg) func resetRecovery(userPrincipal : Principal) : async Result.Result<(), Text> {
    let caller = msg.caller;
    
    // アクセス権限の確認
    let actualPrincipal = await getActualPrincipal(caller);
    
    if (actualPrincipal != userPrincipal) {
      return #err("このリカバリーセッションをリセットする権限がありません");
    };
    
    // セッションを削除
    recoverySessions.delete(userPrincipal);
    return #ok();
  };
  
  public shared (msg) func collectRecoveryData(userToRecover : Principal) : async Result.Result<(RecoverySession, [KeyShare], ?Blob), Text> {
    let caller = msg.caller;
    
    // 回復セッションを取得
    switch (recoverySessions.get(userToRecover)) {
      case null { return #err("リカバリーセッションが見つかりません") };
      case (?session) {
        // 承認済みガーディアンかチェック
        let isApprovedGuardian = Array.find<Principal>(
          session.approvedGuardians,
          func(p : Principal) : Bool { p == caller }
        ) != null;
        
        if (not isApprovedGuardian) {
          return #err("このリカバリーセッションの承認されたガーディアンではありません");
        };
        
        // 承認済みシェアのリストを取得
        let sharesList = Buffer.Buffer<KeyShare>(0);
        
        for (shareId in session.collectedShares.vals()) {
          switch (shares.get(shareId)) {
            case null { /* シェアが見つからない場合はスキップ */ };
            case (?share) {
              sharesList.add(share);
            };
          };
        };
        
        // 公開リカバリーデータを取得
        let publicData = switch (userProfiles.get(userToRecover)) {
          case null { null };
          case (?profile) { profile.publicRecoveryData };
        };
        
        return #ok((session, Buffer.toArray(sharesList), publicData));
      };
    };
  };
  
  // アクセス権限管理
  public shared (msg) func activateRecoveredAccount(
    originalPrincipal : Principal,
    deviceName : Text,
    devicePublicKey : Blob
  ) : async Result.Result<DeviceId, Text> {
    let caller = msg.caller;
    
    // リカバリーアクセスを確認
    switch (recoveryAccesses.get(caller)) {
      case null { return #err("リカバリーアクセスが見つかりません") };
      case (?access) {
        if (access.originalPrincipal != originalPrincipal) {
          return #err("このアカウントのリカバリーアクセス権限がありません");
        };
        
        if (access.isUsed) {
          return #err("このリカバリーアクセスは既に使用されています");
        };
        
        if (Time.now() > access.expiryTime) {
          return #err("リカバリーアクセスの有効期限が切れています");
        };
        
        // 新しいデバイスを追加
        switch (userProfiles.get(originalPrincipal)) {
          case null { return #err("元のユーザープロファイルが見つかりません") };
          case (?profile) {
            let deviceId = generateId("device");
            let device : DeviceInfo = {
              id = deviceId;
              name = deviceName;
              publicKey = devicePublicKey;
              registrationTime = Time.now();
              lastAccessTime = Time.now();
            };
            
            // 新しいデバイスリストを作成
            let deviceBuffer = Buffer.Buffer<DeviceInfo>(profile.devices.size() + 1);
            for (existingDevice in profile.devices.vals()) {
              deviceBuffer.add(existingDevice);
            };
            deviceBuffer.add(device);
            
            let updatedProfile = {
              principal = profile.principal;
              totalGuardians = profile.totalGuardians;
              requiredShares = profile.requiredShares;
              recoveryEnabled = profile.recoveryEnabled;
              publicRecoveryData = profile.publicRecoveryData;
              devices = Buffer.toArray(deviceBuffer);
            };
            
            userProfiles.put(originalPrincipal, updatedProfile);
            
            // アクセスを使用済みにマーク
            let updatedAccess = {
              tempPrincipal = access.tempPrincipal;
              originalPrincipal = access.originalPrincipal;
              accessKey = access.accessKey;
              expiryTime = access.expiryTime;
              isUsed = true;
            };
            
            recoveryAccesses.put(caller, updatedAccess);
            
            return #ok(deviceId);
          };
        };
      };
    };
  };
  
  public shared (msg) func getAccessKey() : async Result.Result<Blob, Text> {
    let caller = msg.caller;
    
    switch (recoveryAccesses.get(caller)) {
      case null { return #err("リカバリーアクセスが見つかりません") };
      case (?access) {
        if (Time.now() > access.expiryTime) {
          return #err("リカバリーアクセスの有効期限が切れています");
        };
        
        return #ok(access.accessKey);
      };
    };
  };
  
  // ユーザー用のシェアを取得するヘルパー関数
  private func getSharesForUser(userPrincipal : Principal) : [KeyShare] {
    let result = Buffer.Buffer<KeyShare>(0);
    
    for ((_, share) in shares.entries()) {
      if (share.userPrincipal == userPrincipal) {
        result.add(share);
      };
    };
    
    return Buffer.toArray(result);
  };
  
  // リカバリーアクセスを考慮した実際のプリンシパルを取得
  private func getActualPrincipal(caller : Principal) : async Principal {
    switch (recoveryAccesses.get(caller)) {
      case null { 
        // 通常のアクセス - 呼び出し元が本人
        return caller;
      };
      case (?access) {
        if (not access.isUsed and Time.now() <= access.expiryTime) {
          // リカバリーアクセス - 元のプリンシパルを返す
          return access.originalPrincipal;
        } else {
          // 期限切れまたは使用済みアクセス - 呼び出し元を返す
          return caller;
        };
      };
    };
  };
  
  // ユニークなIDを生成するヘルパー関数
  private func generateId(prefix : Text) : Text {
    let timestamp = Int.toText(Time.now());
    let random = Int.toText(Time.now() % 10000);
    return prefix # "-" # timestamp # "-" # random;
  };

 // Cycleの現在の残高を取得
  public query func availableCycles() : async Nat {
    Cycles.balance()
  };

  // Cycleを追加するための関数
  // 注意: この関数は通常、フロントエンドやウォレットから呼び出されます
  public func addCycles() : async () {
    let available = Cycles.available();
    let accepted = Cycles.accept(available);
  };

  // Cycleの最小残高を設定（例：10兆cycles）
  private let MIN_CYCLES : Nat = 10_000_000_000_000;

  // Cycleが低残高の場合に警告を返す関数
  public query func checkCycleBalance() : async Result.Result<Text, Text> {
    let currentBalance = Cycles.balance();
    
    if (currentBalance < MIN_CYCLES) {
      #err("サイクル残高が低下しています。補充が必要です。現在の残高: " # Nat.toText(currentBalance) # " cycles")
    } else {
      #ok("サイクル残高は十分です。現在の残高: " # Nat.toText(currentBalance) # " cycles")
    }
  };

}
