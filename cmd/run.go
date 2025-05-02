package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/bitterspread/mediax/config"
	"github.com/bitterspread/mediax/database"
	"github.com/bitterspread/mediax/dataops"
	"github.com/bitterspread/mediax/helpers"
	"github.com/bitterspread/mediax/routes"
	"github.com/bitterspread/mediax/version"
	"golang.org/x/crypto/bcrypt"
)

func Execute() {
	configPath := flag.String("config", "config.json", "指定配置文件路径")
	versionFlag := flag.Bool("version", false, "显示 mediaX 版本信息")
	bcryptFlag := flag.String("bcrypt", "", "生成 bcrypt 加密后的密码")
	apiKey := flag.Bool("api-key", false, "生成一个新的 API Key 及其哈希值")
	importType := flag.String("import", "", "导入数据来源: bangumi 或 douban")
	filePath := flag.String("file", "", "导入文件的相对路径")
	downloadImage := flag.Bool("download-image", false, "可选，导入数据时是否下载图片")
	exportType := flag.String("export", "", "导出数据: all, book, movie, tv, anime, game")
	limit := flag.Int("limit", -1, "可选，指定导出的数量，默认导出所有数据")

	flag.Usage = func() {
		fmt.Println("Document: https://github.com/bitterspread/mediax/README.md")
		fmt.Println("\nAvailable parameters:")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NFlag() == 0 {
		log.Println("Info: No arguments provided. Loading default config file.")
		err := config.LoadConfig("config.json")
		if err != nil {
			log.Printf("Error loading default config: %v\n", err)
			os.Exit(1)
		}
		startServer(config.App.Server.Port)
		return
	}

	usedFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		usedFlags[f.Name] = true
	})

	if *versionFlag {
		if len(usedFlags) > 1 {
			fmt.Println("Error: --version flag must be used alone.")
			os.Exit(1)
		}
		fmt.Println("mediaX", version.Version)
		os.Exit(0)
	}

	if usedFlags["config"] {
		if len(usedFlags) > 1 {
			fmt.Println("Error: --config flag must be used alone.")
			os.Exit(1)
		}
		err := config.LoadConfig(*configPath)
		if err != nil {
			fmt.Println("Error loading config:", err)
			os.Exit(1)
		}
		startServer(config.App.Server.Port)
		return
	}

	if usedFlags["bcrypt"] {
		if len(usedFlags) > 1 {
			fmt.Println("Error: --bcrypt flag must be used alone.")
			flag.Usage()
			os.Exit(1)
		}
		password := *bcryptFlag
		if password == "" {
			fmt.Println("Error: --bcrypt requires a password value.")
			flag.Usage()
			os.Exit(1)
		}

		if len(password) < 4 || len(password) > 64 {
			fmt.Println("Error: Password length must be between 4 and 64 characters.")
			os.Exit(1)
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Println("Error generating bcrypt hash:", err)
			os.Exit(1)
		}

		fmt.Printf("{bcrypt}%s\n", string(hashedPassword))
		os.Exit(0)
	}

	if *apiKey {
		if len(usedFlags) > 1 {
			fmt.Println("Error: --api-key flag must be used alone.")
			os.Exit(1)
		}

		keyLength := 32
		randomBytes, err := helpers.GenerateRandomBytes(keyLength)
		if err != nil {
			log.Fatalf("Failed to generate random bytes for API key: %v", err)
		}
		apiKeyBase64 := base64.URLEncoding.EncodeToString(randomBytes)

		var apiKeyHash string
		hasher := sha256.New()
		hasher.Write([]byte(apiKeyBase64))
		apiKeyHash = base64.StdEncoding.EncodeToString(hasher.Sum(nil))

		fmt.Println("------- Generated API Key -------")
		fmt.Printf("API Key: %s\n", apiKeyBase64)
		fmt.Printf("Hashed API Key: %s\n", apiKeyHash)
		fmt.Println("---------------------------------")
		fmt.Println("Instructions: Copy the 'Hashed API Key' value to your config.json file.")
		fmt.Println("You will use the 'API Key' value when making API requests.")

		os.Exit(0)
	}

	if *importType != "" {
		if *filePath == "" {
			fmt.Println("Error: File path (relative path) is required for data import")
			flag.Usage()
			os.Exit(1)
		}
		database.InitDB()
		err := dataops.ImportFromJSON(*importType, *filePath, *downloadImage)
		if err != nil {
			fmt.Println("Error during import:", err)
			os.Exit(1)
		}
		return
	}
	if *downloadImage && *importType == "" {
		fmt.Println("Error: --download-image is only supported during import")
		flag.Usage()
		os.Exit(1)
	}

	if *exportType != "" {
		database.InitDB()
		err := dataops.ExportToJSON(*exportType, *limit)
		if err != nil {
			fmt.Println("Error during export:", err)
			os.Exit(1)
		}
		return
	}
}

func startServer(port int) {
	database.InitDB()
	routes.Init()

	address := fmt.Sprintf("%s:%d", config.App.Server.Address, port)
	fmt.Print(`
                    _ _      __  __
 _ __ ___   ___  __| (_) __ _\ \/ /
| '_   _ \ / _ \/ _  | |/ _  |\  / 
| | | | | |  __/ (_| | | (_| |/  \ 
|_| |_| |_|\___|\__,_|_|\__,_/_/\_\  by ATP

`)
	fmt.Printf("mediaX %s is running at: http://%s\n", version.Version, address)
	err := http.ListenAndServe(address, nil)
	if err != nil {
		log.Fatalf("mediaX failed to start: %v", err)
	}
}
