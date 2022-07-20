package adrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/rclone/rclone/backend/box/api"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/config/configstruct"
	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/lib/dircache"
	"github.com/rclone/rclone/lib/rest"
)

const (
	itemTypeFolder = "folder"
	itemTypeFile   = "file"
	rootId         = "root"
	rootUrl        = "https://openapi.aliyundrive.com"
	chunkSize      = 10485760
	authorization  = "Authorization"

	//uri
	uriQrcodeLink      = "/oauth/authorize/qrcode"                //获取授权二维码地址
	uriQrcodeImage     = "/oauth/qrcode/%s"                       //获取授权二维码图片
	uriQrcodeStatus    = "/oauth/qrcode/%s/status"                //获取二维码登陆状态
	uriAccessToken     = "/oauth/access_token"                    //获取access_token
	uriDriveId         = "/adrive/v1.0/user/getDriveInfo"         //获取driveId
	uriFileList        = "/adrive/v1.0/openFile/list"             //文件列表
	uriFileDetail      = "/adrive/v1.0/openFile/get"              //获取文件详情
	uriFileDownloadUrl = "/adrive/v1.0/openFile/getDownloadUrl"   //获取下载链接
	uriFileCreate      = "/adrive/v1.0/openFile/create"           //创建
	uriFileUploadUrl   = "/adrive/v1.0/openFile/getUploadUrl"     //刷新获取文件上传地址
	uriFileComplete    = "/adrive/v1.0/openFile/complete"         //完成上传
	uriFileUpdate      = "/adrive/v1.0/openFile/update"           //文件更新
	uriFileMove        = "/adrive/v1.0/openFile/move"             //文件移动
	uriFileCopy        = "/adrive/v1.0/openFile/copy"             //文件复制
	uriFileTrash       = "/adrive/v1.0/openFile/recyclebin/trash" //移动到回收站
	uriSpaceInfo       = "/adrive/v1.0/user/getSpaceInfo"         //获取空间信息
)

// Register with Fs
func init() {
	fs.Register(&fs.RegInfo{
		Name:        "adrive",
		Description: "Aliyun Drive",
		NewFs:       NewFs,
		Config:      Config,
		Options: []fs.Option{{
			Name:     "client_id",
			Help:     "Please enter  clientId",
			Required: true,
		}, {
			Name:     "client_secret",
			Help:     "Please enter clientSecret",
			Required: true,
		}},
	})
}

// NewFs constructs an Fs from the path, bucket:path
func NewFs(ctx context.Context, name, root string, m configmap.Mapper) (fs.Fs, error) {
	opt := new(Options)
	err := configstruct.Set(m, opt)
	if err != nil {
		return nil, err
	}

	f := &Fs{
		name: name,
		srv:  rest.NewClient(fshttp.NewClient(ctx)),
		cli:  rest.NewClient(fshttp.NewClient(ctx)),
		opt:  *opt,
		root: root,
		ctx:  ctx,
		m:    m,
	}

	f.features = (&fs.Features{
		CanHaveEmptyDirectories: true,
	}).Fill(ctx, f)

	f.reWriteConfig(ctx, name)
	f.dirCache = dircache.New(root, rootId, f)
	f.getDriveId(ctx)
	return f, err
}

func (f *Fs) getDriveId(ctx context.Context) error {
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriDriveId,
		RootURL: rootUrl,
	}
	d := DriveIdOut{}

	err := f.callJSON(f.ctx, &opts, nil, &d)
	if err != nil {
		return err
	}
	f.driveId = d.DefaultDriveId
	return nil
}

func (f *Fs) reWriteConfig(ctx context.Context, name string) {
	for {
		t, err := time.ParseInLocation("2006-01-02 15:04:05", f.opt.ExpiresAt, time.Local)
		if err != nil {
			t = time.Now()
		}
		sub := time.Until(t)
		if sub < 0 {
			sub = 5 * time.Minute
		}
		trigger := time.After(sub)
		<-trigger
		f.getAccessToken()
	}
}

// getAccessToken 获取getAccessToken
func (f *Fs) getAccessToken() error {
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriAccessToken,
		RootURL: rootUrl,
	}
	request := AccessTokenIn{
		RefreshToken: f.opt.RefreshToken,
		ClientId:     f.opt.ClientId,
		ClientSecret: f.opt.ClientSecret,
		GrantType:    "refresh_token",
	}
	token := AccessTokenOut{}

	err := f.callJSON(f.ctx, &opts, request, &token)
	if err != nil {
		return err
	}
	if token.AccessToken != "" && token.ExpiresIn != 0 && token.RefreshToken != "" {
		f.m.Set("token_type", token.TokenType)
		f.m.Set("access_token", token.AccessToken)
		f.m.Set("refresh_token", token.RefreshToken)
		f.m.Set("expires_at", time.Now().Add(time.Duration(token.ExpiresIn-600)*time.Second).Format("2006-01-02 15:04:05"))
		return configstruct.Set(f.m, f.opt)
	} else {
		return errors.New("get accessToken or refreshToken error")
	}
}

func (f *Fs) callJSON(ctx context.Context, opts *rest.Opts, request interface{}, response interface{}) error {
	if opts != nil {
		opts.OriginResponse = true
	}
	if opts.RootURL == rootUrl {
		f.srv.SetHeader(authorization, f.opt.TokenType+" "+f.opt.AccessToken)
	}
	_, err := f.srv.CallJSON(ctx, opts, request, response)
	if err != nil {
		return err
	}
	return nil
}

// Config callback
func Config(ctx context.Context, name string, m configmap.Mapper, c fs.ConfigIn) (*fs.ConfigOut, error) {
	clientId, ok := m.Get("client_id")
	if !ok {
		return nil, errors.New("clientId not found")
	}

	secret, ok := m.Get("client_secret")
	if !ok {
		return nil, errors.New("secret not found")
	}

	linkOut, err := getQrcodeLink(ctx, clientId, secret)
	if err != nil {
		return nil, err
	}

	fmt.Printf("请在浏览器中打开二维码图片并扫码授权：%s \n", linkOut.QrcodeLink)

	var authCode string
	for {
		status, err := getQrcodeStatus(ctx, linkOut.Sid)
		if err == nil && status.Status == "LoginSuccess" && status.AuthCode != "" {
			authCode = status.AuthCode
			break
		}
		time.Sleep(time.Second * 5)
	}

	token, err := getAccessToken(ctx, clientId, secret, authCode)
	if err != nil {
		return nil, err
	}

	if token.AccessToken != "" && token.ExpiresIn != 0 && token.RefreshToken != "" {
		m.Set("token_type", token.TokenType)
		m.Set("access_token", token.AccessToken)
		m.Set("refresh_token", token.RefreshToken)
		m.Set("expires_at", time.Now().Add(time.Duration(token.ExpiresIn-600)*time.Second).Format("2006-01-02 15:04:05"))
		return nil, nil
	} else {
		return nil, errors.New("error get access_token")
	}
}

func getAccessToken(ctx context.Context, clientId, secret, code string) (*AccessTokenOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriAccessToken,
	}
	req := &AccessTokenIn{
		ClientId:     clientId,
		ClientSecret: secret,
		Code:         code,
		GrantType:    "authorization_code",
	}

	resp := &AccessTokenOut{}
	_, err := c.CallJSON(ctx, opts, req, resp)
	return resp, err
}

func getQrcodeStatus(ctx context.Context, sid string) (*QrcodeStatusOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  "GET",
		RootURL: rootUrl,
		Path:    fmt.Sprintf(uriQrcodeStatus, sid),
	}
	resp := &QrcodeStatusOut{}
	_, err := c.CallJSON(ctx, opts, nil, resp)
	return resp, err
}

func getQrcodeLink(ctx context.Context, clientId, secret string) (*QrcodeLinkOut, error) {
	c := rest.NewClient(fshttp.NewClient(ctx))
	opts := &rest.Opts{
		Method:  "POST",
		RootURL: rootUrl,
		Path:    uriQrcodeLink,
	}
	req := &QrcodeLinkIn{
		ClientId:     clientId,
		ClientSecret: secret,
		Scopes:       []string{"user:base", "user:phone", "file:all:read", "file:all:write"},
	}

	resp := &QrcodeLinkOut{}
	_, err := c.CallJSON(ctx, opts, req, resp)
	return resp, err
}

type Fs struct {
	name     string
	srv      *rest.Client
	cli      *rest.Client
	features *fs.Features
	opt      Options
	root     string
	ctx      context.Context
	driveId  string
	m        configmap.Mapper
	dirCache *dircache.DirCache // Map of directory path to directory id
}

// Options defines the configuration for this backend
type Options struct {
	ClientId     string `config:"client_id"`
	ClientSecret string `config:"client_secret"`
	TokenType    string `config:"token_type"`
	AccessToken  string `config:"access_token"`
	RefreshToken string `config:"refresh_token"`
	ExpiresAt    string `config:"expires_at"`
}

// Name 返回名称
func (f *Fs) Name() string {
	return f.name
}

// Root of the remote (as passed into NewFs)
func (f *Fs) Root() string {
	return f.root
}

// String converts this Fs to a string
func (f *Fs) String() string {
	return "Aliyun Drive"
}

// Features returns the optional features of this Fs
func (f *Fs) Features() *fs.Features {
	return f.features
}

func (f *Fs) Precision() time.Duration {
	return time.Second
}

func (f *Fs) Hashes() hash.Set {
	return 0
}

func (f *Fs) List(ctx context.Context, dir string) (entries fs.DirEntries, err error) {
	directoryID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return nil, err
	}

	list, err := f.listAll(ctx, directoryID)
	for _, info := range list {
		remote := path.Join(dir, info.Name)
		if info.Type == itemTypeFolder {
			f.dirCache.Put(remote, info.FileId)
			d := fs.NewDir(remote, info.UpdatedAt).SetID(info.FileId).SetParentID(dir)
			entries = append(entries, d)
		} else {
			o, err := f.newObjectWithInfo(ctx, remote, &info)
			if err == nil {
				entries = append(entries, o)
			}
		}
	}
	return
}

// listAll 获取目录下全部文件
func (f *Fs) listAll(ctx context.Context, parentFileId string) ([]ItemOut, error) {
	request := ListIn{
		Limit:          100,
		DriveId:        f.driveId,
		ParentFileId:   parentFileId,
		OrderBy:        "name",
		OrderDirection: "ASC",
		Fields:         "*",
	}

	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileList,
		RootURL: rootUrl,
	}

	var out []ItemOut
	for {
		resp := ListOut{}
		err := f.callJSON(ctx, &opts, request, &resp)
		if err != nil {
			return out, err
		}
		out = append(out, resp.Items...)
		if resp.NextMarker == "" {
			break
		} else {
			//限流
			time.Sleep(time.Millisecond * 250)
			request.Marker = resp.NextMarker
		}
	}
	return out, nil
}

// isDirEmpty 判断目录是否为空
func (f *Fs) isDirEmpty(ctx context.Context, parentFileId string) bool {
	request := ListIn{
		Limit:        1,
		DriveId:      f.driveId,
		ParentFileId: parentFileId,
		Fields:       "*",
	}

	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileList,
		RootURL: rootUrl,
	}
	resp := ListOut{}
	err := f.callJSON(ctx, &opts, request, &resp)
	if err != nil {
		return false
	}
	return len(resp.Items) == 0
}

func (f *Fs) NewObject(ctx context.Context, remote string) (fs.Object, error) {
	return f.newObjectWithInfo(ctx, remote, nil)
}

func (f *Fs) Copy(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		return nil, fs.ErrorCantCopy
	}
	err := srcObj.readMetaData(ctx)
	if err != nil {
		return nil, err
	}

	srcPath := srcObj.remote
	dstPath := remote
	if strings.EqualFold(strings.ToLower(srcPath), strings.ToLower(dstPath)) {
		return nil, fmt.Errorf("can't copy %q -> %q as are same name when lowercase", srcPath, dstPath)
	}
	// Create temporary object
	dstObj, _, directoryID, err := f.createObject(ctx, remote, srcObj.modTime, srcObj.size)
	if err != nil {
		return nil, err
	}
	request := FileCopyIn{
		DriveId:        f.driveId,
		FileId:         srcObj.id,
		ToParentFileId: directoryID,
	}
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileCopy,
		RootURL: rootUrl,
	}
	var response FileOperateOut
	err = f.callJSON(ctx, &opts, request, &response)
	if err != nil {
		return nil, err
	}
	if err := dstObj.GetFileInfo(ctx); err != nil {
		return nil, err
	}
	return dstObj, nil
}

func (f *Fs) Move(ctx context.Context, src fs.Object, remote string) (fs.Object, error) {
	srcObj, ok := src.(*Object)
	if !ok {
		fs.Debugf(src, "Can't move - not same remote type")
		return nil, fs.ErrorCantMove
	}

	// Create temporary object
	dstObj, leaf, directoryID, err := f.createObject(ctx, remote, srcObj.modTime, srcObj.size)
	if err != nil {
		return nil, err
	}

	request := FileMoveIn{
		DriveId:        f.driveId,
		FileId:         srcObj.id,
		ToParentFileId: directoryID,
		NewName:        leaf,
		CheckNameMode:  "auto_rename",
	}
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileMove,
		RootURL: rootUrl,
	}
	// var response FileCopyOut
	var response interface{}
	err = f.callJSON(ctx, &opts, request, &response)
	if err != nil {
		return nil, err
	}
	json.Marshal(response)
	if err := dstObj.GetFileInfo(ctx); err != nil {
		return nil, err
	}
	return dstObj, nil
}

// Put TODO
func (f *Fs) Put(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	_, _, err := f.dirCache.FindPath(ctx, remote, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			return f.PutUnchecked(ctx, in, src, options...)
		}
		return nil, err
	}
	return f.PutUnchecked(ctx, in, src, options...)
}

// PutUnchecked the object into the container
//
// # This will produce an error if the object already exists
//
// # Copy the reader in to the new object which is returned
//
// The new object may have been created if an error is returned
func (f *Fs) PutUnchecked(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (fs.Object, error) {
	remote := src.Remote()
	size := src.Size()
	modTime := src.ModTime(ctx)

	o, _, _, err := f.createObject(ctx, remote, modTime, size)
	if err != nil {
		return nil, err
	}
	return o, o.Update(ctx, in, src, options...)
}

// setMetaData sets the metadata from info
func (o *Object) setMetaData(info *ItemOut) (err error) {
	if info.Type == itemTypeFolder {
		return fs.ErrorIsDir
	}
	if info.Type != api.ItemTypeFile {
		return fmt.Errorf("%q is %q: %w", o.remote, info.Type, fs.ErrorNotAFile)
	}
	o.hasMetaData = true
	o.size = int64(info.Size)
	o.sha1 = info.ContentHash
	o.modTime = info.CreatedAt
	o.id = info.FileId
	return nil
}

// Creates from the parameters passed in a half finished Object which
// must have setMetaData called on it
//
// # Returns the object, leaf, directoryID and error
//
// Used to create new objects
func (f *Fs) createObject(ctx context.Context, remote string, modTime time.Time, size int64) (o *Object, leaf string, directoryID string, err error) {
	// Create the directory for the object if it doesn't exist
	leaf, directoryID, err = f.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return
	}
	// Temporary Object under construction
	o = &Object{
		fs:     f,
		remote: remote,
	}
	return o, leaf, directoryID, nil
}

func (f *Fs) Mkdir(ctx context.Context, dir string) error {
	_, err := f.dirCache.FindDir(ctx, dir, true)
	return err
}

// Rmdir 删除空目录
func (f *Fs) Rmdir(ctx context.Context, dir string) error {
	directoryID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return err
	}
	if directoryID == rootId {
		return errors.New("the root directory cannot be deleted")
	}
	if !f.isDirEmpty(ctx, directoryID) {
		return errors.New("directory is not be empty")
	}
	err = f.deleteObject(ctx, directoryID)
	if err == nil {
		f.dirCache.FlushDir(dir)
	}
	return err
}

// 删除操作
func (f *Fs) deleteObject(ctx context.Context, fileId string) error {
	request := FileTrashIn{
		DriveId: f.driveId,
		FileId:  fileId,
	}

	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileTrash,
		RootURL: rootUrl,
	}
	var response FileOperateOut
	err := f.callJSON(ctx, &opts, request, &response)
	return err
}

// Purge deletes all the files and the container
//
// Optional interface: Only implement this if you have a way of
// deleting all the files quicker than just running Remove() on the
// result of List()
func (f *Fs) Purge(ctx context.Context, dir string) error {
	directoryID, err := f.dirCache.FindDir(ctx, dir, false)
	if err != nil {
		return err
	}
	err = f.deleteObject(ctx, directoryID)
	if err == nil {
		f.dirCache.FlushDir(dir)
	}
	return err
}

// FindLeaf finds a directory of name leaf in the folder with ID pathID
func (f *Fs) FindLeaf(ctx context.Context, pathID, leaf string) (pathIDOut string, found bool, err error) {
	// Find the leaf in pathID
	items, err := f.listAll(f.ctx, pathID)
	if err != nil {
		return
	}
	for _, item := range items {
		if item.Name == leaf {
			pathIDOut = item.FileId
			found = true
		}
	}
	return
}

// CreateDir makes a directory with pathID as parent and name leaf
func (f *Fs) CreateDir(ctx context.Context, pathID, leaf string) (newID string, err error) {
	request := MakeDirIn{
		CheckNameMode: "refuse",
		DriveId:       f.driveId,
		Type:          itemTypeFolder,
		Name:          leaf,
		ParentFileId:  pathID, //
	}
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileCreate,
		RootURL: rootUrl,
	}
	var response FileOperateOut

	err = f.callJSON(ctx, &opts, request, &response)
	return response.FileId, err
}

// About gets quota information
func (f *Fs) About(ctx context.Context) (usage *fs.Usage, err error) {
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriSpaceInfo,
		RootURL: rootUrl,
	}
	var resp SpaceOut
	err = f.callJSON(ctx, &opts, nil, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info: %w", err)
	}
	usage = &fs.Usage{
		Used:  fs.NewUsageValue(resp.PersonalSpaceInfo.UsedSize),                                    // bytes in use
		Total: fs.NewUsageValue(resp.PersonalSpaceInfo.TotalSize),                                   // bytes total
		Free:  fs.NewUsageValue(resp.PersonalSpaceInfo.TotalSize - resp.PersonalSpaceInfo.UsedSize), // bytes free
	}
	return usage, nil
}

// DirCacheFlush resets the directory cache - used in testing as an
// optional interface
func (f *Fs) DirCacheFlush() {
	f.dirCache.ResetRoot()
}

type Object struct {
	fs          *Fs       // what this object is part of
	remote      string    // The remote path
	size        int64     // size of the object
	modTime     time.Time // modification time of the object
	id          string    // ID of the object
	sha1        string    // SHA-1 of the object content
	hasMetaData bool      //
}

// If it can't be found it returns the error fs.ErrorObjectNotFound.
func (f *Fs) newObjectWithInfo(ctx context.Context, remote string, info *ItemOut) (fs.Object, error) {
	o := &Object{
		fs:     f,
		remote: remote,
	}
	var err error
	if info != nil {
		err = o.setMetaData(info)
	} else {
		err = o.readMetaData(ctx)
	}
	return o, err
}

func (o *Object) readMetaData(ctx context.Context) (err error) {
	if o.hasMetaData {
		return nil
	}
	leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, o.remote, false)
	if err != nil {
		if err == fs.ErrorDirNotFound {
			return fs.ErrorObjectNotFound
		}
		return err
	}

	list, err := o.fs.listAll(ctx, directoryID)
	if err != nil {
		return err
	}
	var info ItemOut
	for _, v := range list {
		if v.Type == itemTypeFile && strings.EqualFold(v.Name, leaf) {
			info = v
			break
		}
	}
	return o.setMetaData(&info)
}

// Fs returns the parent Fs
func (o *Object) Fs() fs.Info {
	return o.fs
}

// Return a string version
func (o *Object) String() string {
	if o == nil {
		return "<nil>"
	}
	return o.remote
}

// Remote returns the remote path
func (o *Object) Remote() string {
	return o.remote
}

// Hash returns the SHA-1 of an object returning a lowercase hex string
func (o *Object) Hash(ctx context.Context, t hash.Type) (string, error) {
	if t != hash.SHA1 {
		return "", hash.ErrUnsupported
	}
	return o.sha1, nil
}

// Size returns the size of an object in bytes
func (o *Object) Size() int64 {
	return o.size
}

// ModTime returns the modification time of the object
//
// It attempts to read the objects mtime and if that isn't present the
// LastModified returned in the http headers
func (o *Object) ModTime(ctx context.Context) time.Time {
	return o.modTime
}

// SetModTime sets the modification time of the local fs object
func (o *Object) SetModTime(ctx context.Context, modTime time.Time) error {
	return nil
}

// Storable returns a boolean showing whether this object storable
func (o *Object) Storable() bool {
	return true
}

// Open an object for read
func (o *Object) Open(ctx context.Context, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	req := DownloadIn{
		DriveId:   o.fs.driveId,
		FileId:    o.id,
		ExpireSec: 115200,
	}
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileDownloadUrl,
		RootURL: rootUrl,
	}
	resp := DownloadOut{}
	err = o.fs.callJSON(ctx, &opts, req, &resp)
	if err != nil {
		return nil, err
	}
	return o.download(ctx, resp, options...)
}

func (o *Object) download(ctx context.Context, info DownloadOut, options ...fs.OpenOption) (in io.ReadCloser, err error) {
	fs.FixRangeOption(options, o.size)
	var resp *http.Response
	opts := rest.Opts{
		Method:  info.Method,
		RootURL: info.Url,
		Options: options,
	}
	resp, err = o.fs.cli.Call(ctx, &opts)
	if err != nil {
		return nil, err
	}
	return resp.Body, err
}

// Update the object with the contents of the io.Reader, modTime and size
//
// # If existing is set then it updates the object rather than creating a new one
//
// The new object may have been created if an error is returned
func (o *Object) Update(ctx context.Context, in io.Reader, src fs.ObjectInfo, options ...fs.OpenOption) (err error) {
	size := src.Size()
	modTime := src.ModTime(ctx)
	remote := o.Remote()

	leaf, directoryID, err := o.fs.dirCache.FindPath(ctx, remote, true)
	if err != nil {
		return err
	}
	return o.upload(ctx, in, leaf, directoryID, modTime, size)
}

// 上传
func (o *Object) upload(ctx context.Context, in io.Reader, leaf, directoryID string, modTime time.Time, size int64) (err error) {
	chunkNum := int(math.Ceil(float64(size) / chunkSize))
	resp, err := o.preUpload(ctx, leaf, directoryID, modTime, size, chunkNum)
	if err != nil {
		return err
	}
	if len(resp.PartInfoList) != chunkNum {
		return errors.New("预上传数量和分片数不一致")
	}
	//设置file_id
	o.id = resp.FileId
	//分片上传
	err = o.sliceUpload(ctx, resp.PartInfoList, in, size, int64(chunkNum))
	if err != nil {
		return err
	}
	//上传完成
	return o.complete(ctx, resp.FileId, resp.UploadId)
}

// 预上传
func (o *Object) preUpload(ctx context.Context, leaf, directoryID string, modTime time.Time, size int64, chunkNum int) (FileCreateOut, error) {
	req := FileCreateIn{
		DriveId:         o.fs.driveId,
		Name:            leaf,
		ParentFileId:    directoryID,
		Size:            size,
		CheckNameMode:   "refuse",
		ContentHashName: "none",
		ProofVersion:    "v1",
		Type:            "file",
		PartInfoList:    make([]PartInfo, 0),
	}
	for i := 0; i < chunkNum; i++ {
		req.PartInfoList = append(req.PartInfoList, PartInfo{PartNumber: i + 1})
	}
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileCreate,
		RootURL: rootUrl,
	}
	resp := FileCreateOut{}
	err := o.fs.callJSON(ctx, &opts, req, &resp)
	return resp, err
}

// 分片上传
func (o *Object) sliceUpload(ctx context.Context, parts []PartInfo, in io.Reader, size int64, chukNum int64) (err error) {
	// 先串行上传，后期改成并行
	for k, p := range parts {
		newChunkSize := int64(chunkSize)
		if k == int(chukNum-1) {
			newChunkSize = size - chunkSize*int64(chukNum-1)
		}
		buf := make([]byte, newChunkSize)
		io.ReadFull(in, buf)
		uploadUrl := p.UploadUrl

		opts := rest.Opts{
			Method:  "PUT",
			RootURL: uploadUrl,
			Body:    bytes.NewReader(buf),
		}
		_, err = o.fs.cli.Call(ctx, &opts)
		if err != nil {
			return err
		}
	}
	return err
}

// 完成上传
func (o *Object) complete(ctx context.Context, fileId, uploadId string) error {
	rep := FileUploadCompleteIn{
		DriveId:  o.fs.driveId,
		FileId:   fileId,
		UploadId: uploadId,
	}
	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileComplete,
		RootURL: rootUrl,
	}

	err := o.fs.callJSON(ctx, &opts, rep, nil)
	if err != nil {
		return err
	}
	return o.GetFileInfo(ctx)
}

func (o *Object) GetFileInfo(ctx context.Context) error {
	in := FileInfoIn{
		DriveId: o.fs.driveId,
		FileId:  o.id,
	}

	opts := rest.Opts{
		Method:  "POST",
		Path:    uriFileDetail,
		RootURL: rootUrl,
	}

	out := ItemOut{}

	err := o.fs.callJSON(ctx, &opts, in, &out)
	if err != nil {
		return err
	}
	return o.setMetaData(&out)

}

// Remove an object
func (o *Object) Remove(ctx context.Context) error {
	return o.fs.deleteObject(ctx, o.id)
}

// ID returns the ID of the Object if known, or "" if not
func (o *Object) ID() string {
	return o.id
}
