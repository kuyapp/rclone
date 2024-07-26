package adrive

import "time"

type QrcodeLinkIn struct {
	ClientId     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	Scopes       []string `json:"scopes"`
}

type QrcodeLinkOut struct {
	QrcodeLink string `json:"qrCodeUrl"`
	Sid        string `json:"sid"`
}

type QrcodeStatusOut struct {
	Status   string `json:"status"`
	AuthCode string `json:"authCode"`
}

type AccessTokenIn struct {
	ClientId     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RefreshToken string `json:"refresh_token"`
}

type AccessTokenOut struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

type DriveIdOut struct {
	DefaultDriveId string `json:"resource_drive_id"`
}

// list 查询参数
type ListIn struct {
	DriveId             string `json:"drive_id"`              //必填 drive id
	Limit               int    `json:"limit"`                 //选填 返回文件数量，默认 50，最大 100
	Marker              string `json:"marker"`                //选填 分页标记
	OrderBy             string `json:"order_by"`              //选填 排序字段，created_at,updated_at,name,size
	OrderDirection      string `json:"order_direction"`       //选填 DESC ASC
	ParentFileId        string `json:"parent_file_id"`        //必填 根目录为root
	Category            string `json:"category"`              //选填 分类，目前有枚举：video|doc|audio|zip|others|image 可任意组合，按照逗号分割，例如 video,doc,audio image,doc
	Type                string `json:"type"`                  //选填 all|file|folder，默认所有类型 type为folder时，category不做检查
	VideoThumbnailTime  int    `json:"video_thumbnail_time"`  //选填 生成的视频缩略图截帧时间，单位ms，默认120000ms
	VideoThumbnailWidth int    `json:"video_thumbnail_width"` //选填 生成的视频缩略图宽度，默认480px
	ImageThumbnailWidth int    `json:"image_thumbnail_width"` //选填 生成的图片缩略图宽度，默认480px
	Fields              string `json:"fields"`                //选填 当填 * 时，返回文件所有字段；当只需要特定字段时，可设置为：url、thumbnail、video_metadata，当需要多个字段时，以逗号 , 分割，如 url,thumbnail
}

type ListOut struct {
	Items      []ItemOut `json:"items"`
	NextMarker string    `json:"next_marker"` //下个分页标记
}

type ItemOut struct {
	DriveId       string    `json:"drive_id"`       //drive id
	FileId        string    `json:"file_id"`        //file_id
	ParentFileId  string    `json:"parent_file_id"` //父目录id
	Name          string    `json:"name"`           //文件名
	Size          int64     `json:"size"`           //
	FileExtension string    `json:"file_extension"` //
	ContentHash   string    `json:"content_hash"`   //文件hash
	Category      string    `json:"category"`       //
	Type          string    `json:"type"`           //file | folderq
	Thumbnail     string    `json:"thumbnail"`      //缩略图
	Url           string    `json:"url"`            //预览
	CreatedAt     time.Time `json:"created_at"`     //格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
	UpdatedAt     time.Time `json:"updated_at"`     //格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
}

type FileInfoIn struct {
	DriveId             string `json:"drive_id"`              //必填 drive id
	FileId              string `json:"file_id"`               //必填 file_id
	Category            string `json:"category"`              //
	VideoThumbnailTime  int    `json:"video_thumbnail_time"`  //选填 生成的视频缩略图截帧时间，单位ms，默认120000ms
	VideoThumbnailWidth int    `json:"video_thumbnail_width"` //选填 生成的视频缩略图宽度，默认480px
	ImageThumbnailWidth int    `json:"image_thumbnail_width"` //选填 生成的图片缩略图宽度，默认480px
}

type DownloadIn struct {
	DriveId   string `json:"drive_id"`
	FileId    string `json:"file_id"`
	ExpireSec int64  `json:"expire_sec"`
}

type DownloadOut struct {
	Url        string `json:"url"`        //必填 下载地址
	Expiration string `json:"expiration"` //必填 过期时间 格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
	Method     string `json:"method"`     //必填 下载方法
}

type FileCreateIn struct {
	DriveId         string     `json:"drive_id"`          //必填 drive id
	ParentFileId    string     `json:"parent_file_id"`    //必填 父目录id，上传到根目录时填写 root
	Name            string     `json:"name"`              //必填 文件名称，按照 utf8 编码最长 1024 字节，不能以 / 结尾
	Type            string     `json:"type"`              //必填 file | folder
	CheckNameMode   string     `json:"check_name_mode"`   //必填 auto_rename 自动重命名，存在并发问题 refuse 同名不创建 ignore 同名文件可创建
	PartInfoList    []PartInfo `json:"part_info_list"`    //选填 最大分片数量 10000
	PreHash         string     `json:"pre_hash"`          //选填 针对大文件sha1计算非常耗时的情况， 可以先在读取文件的前1k的sha1， 如果前1k的sha1没有匹配的， 那么说明文件无法做秒传， 如果1ksha1有匹配再计算文件sha1进行秒传，这样有效边避免无效的sha1计算。
	Size            int64      `json:"size"`              //选填 秒传必须 文件大小，单位为 byte
	ContentHash     string     `json:"content_hash"`      //选填 文件内容 hash 值，需要根据 content_hash_name 指定的算法计算，当前都是sha1算法
	ContentHashName string     `json:"content_hash_name"` //选填 秒传必须 默认都是 sha1
	ProofCode       string     `json:"proof_code"`        //选填 秒传必须
	ProofVersion    string     `json:"proof_version"`     //选填 固定 v1
	LocalCreatedAt  string     `json:"local_created_at"`  //选填 本地创建时间，格式yyyy-MM-dd'T'HH:mm:ss.SSS'Z'
	LocalModifiedAt string     `json:"local_modified_at"` //选填 本地修改时间，格式yyyy-MM-dd'T'HH:mm:ss.SSS'Z'
}

type FileCreateOut struct {
	DriveId      string     `json:"drive_id"`       //必填
	FileId       string     `json:"file_id"`        //必填
	Status       string     `json:"status"`         //必填
	ParentFileId string     `json:"parent_file_id"` //必填
	UploadId     string     `json:"upload_id"`      //选填 创建文件夹返回空
	FileName     string     `json:"file_name"`      //必填
	Available    bool       `json:"available"`      //必填
	Exist        bool       `json:"exist"`          //必填 是否存在同名文件
	RapidUpload  bool       `json:"rapid_upload"`   //必填 是否秒传
	PartInfoList []PartInfo `json:"part_info_list"` //必填
}

type PartInfo struct {
	PartNumber int    `json:"part_number"`
	UploadUrl  string `json:"upload_url"`
	PartSize   int64  `json:"part_size"`
}

type FileUploadCompleteIn struct {
	DriveId  string `json:"drive_id"`  //必填 drive id
	FileId   string `json:"file_id"`   //必填 file_id
	UploadId string `json:"upload_id"` //必填 文件创建获取的upload_id
}

type FileUploadCompleteOut struct {
	DriveId       string `json:"drive_id"`       //必填 drive id
	FileId        string `json:"file_id"`        //必填 file_id
	Name          string `json:"name"`           //必填 文件名
	Size          int64  `json:"size"`           //必填
	FileExtension string `json:"file_extension"` //必填
	ContentHash   string `json:"content_hash"`   //必填 文件hash
	Category      string `json:"category"`       //必填
	Type          string `json:"type"`           //必填 file | folder
	Thumbnail     string `json:"thumbnail"`      //选填 缩略图
	Url           string `json:"url"`            //选填 预览
	DownloadUrl   string `json:"download_url"`   //选填 下载地址
	CreatedAt     string `json:"created_at"`     //必填 格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
	UpdatedAt     string `json:"updated_at"`     //必填 格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
}

type FileUpdateIn struct {
	DriveId       string `json:"drive_id"`        //必填 drive id
	FileId        string `json:"file_id"`         //必填 file_id
	Name          string `json:"name"`            //否 新的文件名
	CheckNameMode string `json:"check_name_mode"` //否 auto_rename 自动重命名 refuse同名不创建 ignore同名文件可创建。 默认
	Starred       bool   `json:"starred"`         //否 收藏 true，移除收藏 false
}

type FileUpdateOut struct {
	DriveId       string `json:"drive_id"`       //必填 drive id
	FileId        string `json:"file_id"`        //必填 file_id
	Name          string `json:"name"`           //必填 文件名
	Size          int    `json:"size"`           //必填
	FileExtension string `json:"file_extension"` //必填
	ContentHash   string `json:"content_hash"`   //必填 文件hash
	Category      string `json:"category"`       //必填
	Type          string `json:"type"`           //必填 file | folder
	CreatedAt     string `json:"created_at"`     //必填 格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
	UpdatedAt     string `json:"updated_at"`     //必填 格式："yyyy-MM-dd'T'HH:mm:ss.SSS'Z'"
}

type MakeDirIn struct {
	DriveId       string `json:"drive_id"`
	Name          string `json:"name"`
	ParentFileId  string `json:"parent_file_id"`
	Type          string `json:"type"`
	CheckNameMode string `json:"check_name_mode"`
}

type FileMoveIn struct {
	DriveId        string `json:"drive_id"`          //必填 drive id
	FileId         string `json:"file_id"`           //必填 file_id
	ToParentFileId string `json:"to_parent_file_id"` //必填 父文件ID、根目录为 root
	CheckNameMode  string `json:"check_name_mode"`   //否 同名文件处理模式，可选值如下：ignore：允许同名文件；auto_rename：当发现同名文件是，云端自动重命名。refuse：当云端存在同名文件时，拒绝创建新文件。默认为 refuse
	NewName        string `json:"new_name"`          //否 当云端存在同名文件时，使用的新名字
}

type FileOperateOut struct {
	DriveId     string `json:"drive_id"`      //必填 drive id
	FileId      string `json:"file_id"`       //必填 file_id
	AsyncTaskId string `json:"async_task_id"` //否 异步任务id。如果返回为空字符串，表示直接移动成功。如果返回非空字符串，表示需要经过异步处理。
	Exist       bool   `json:"exist"`         //必填 文件是否已存在
}

type FileCopyIn struct {
	DriveId        string `json:"drive_id"`          //必填 drive id
	FileId         string `json:"file_id"`           //必填 file_id
	ToParentFileId string `json:"to_parent_file_id"` //必填 父文件ID、根目录为 root
	AutoRename     bool   `json:"auto_rename"`       //否 当目标文件夹下存在同名文件时，是否自动重命名，默认为 false，默认允许同名文件
}

type FileTrashIn struct {
	DriveId string `json:"drive_id"` //必填 drive id
	FileId  string `json:"file_id"`  //必填 file_id
}

type SpaceOut struct {
	PersonalSpaceInfo struct {
		UsedSize  int64 `json:"used_size"`
		TotalSize int64 `json:"total_size"`
	} `json:"personal_space_info"`
}
